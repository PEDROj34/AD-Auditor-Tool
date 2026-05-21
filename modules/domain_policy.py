"""
modules/domain_policy.py — Módulo 7: Política de Password do Domínio.

Queries LDAP:
  1. Objeto de domínio (BASE_DN) — política de password predefinida:
     - minPwdLength, maxPwdAge, minPwdAge, pwdHistoryLength
     - pwdProperties (bitmask — bit 0 = complexidade ativa)
     - lockoutThreshold, lockoutDuration, lockoutObservationWindow

  2. CN=Password Settings Container — Fine-Grained Password Policies (PSOs):
     - Políticas específicas aplicadas a utilizadores ou grupos específicos
     - Têm precedência sobre a política predefinida quando aplicadas

Conversão de atributos Large Integer:
  - maxPwdAge / minPwdAge / lockoutDuration / lockoutObservationWindow são
    intervalos de tempo em 100-nanosegundos negativos (valor 0 = sem limite).
  - pwdProperties é uma bitmask: bit 0 = DOMAIN_PASSWORD_COMPLEX.
"""

from ldap3 import Connection, SUBTREE, BASE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import get_attr
import config


# ─── Helpers de conversão ──────────────────────────────────────────────────────

def _large_int_to_days(val) -> int | None:
    """Converte Large Integer negativo (100-ns intervals) para dias."""
    if val is None:
        return None
    try:
        v = int(val)
        if v == 0:
            return 0  # sem limite / nunca expira
        return abs(v) // 10_000_000 // 86400
    except (ValueError, TypeError):
        return None


def _large_int_to_minutes(val) -> int | None:
    """Converte Large Integer negativo (100-ns intervals) para minutos."""
    if val is None:
        return None
    try:
        v = int(val)
        if v == 0:
            return 0
        return abs(v) // 10_000_000 // 60
    except (ValueError, TypeError):
        return None


def _multival(entry, attr_name: str) -> list:
    """Lê atributos multi-valor com nomes hifenizados."""
    try:
        vals = entry.entry_attributes_as_dict.get(attr_name, [])
        if isinstance(vals, str):
            return [vals]
        return [v for v in vals if v is not None] if vals else []
    except Exception:
        return []


# ─── Avaliação de segurança das configurações ──────────────────────────────────

def _evaluate_settings(raw: dict) -> tuple[list, str]:
    """
    Avalia as configurações da política e devolve:
      - lista de settings formatados com status (ok/warning/critical)
      - severidade global
    """
    settings = []

    # Comprimento mínimo de password
    min_len = raw.get("min_pwd_length", 0) or 0
    if min_len < 8:
        status, rec = "critical", "Mínimo recomendado: 12 caracteres"
    elif min_len < 12:
        status, rec = "warning", "Recomendado aumentar para 12 ou mais"
    else:
        status, rec = "ok", "Comprimento adequado"
    settings.append({
        "name": "Comprimento Mínimo", "value": f"{min_len} caracteres",
        "status": status, "recommendation": rec,
    })

    # Complexidade
    complex_on = raw.get("complexity_enabled", False)
    settings.append({
        "name": "Complexidade",
        "value": "Ativa" if complex_on else "Inativa",
        "status": "ok" if complex_on else "critical",
        "recommendation": "" if complex_on else "Ativar complexidade obrigatória",
    })

    # Idade máxima da password
    max_age = raw.get("max_pwd_age_days")
    if max_age == 0 or max_age is None:
        settings.append({
            "name": "Validade Máxima", "value": "Nunca expira",
            "status": "warning", "recommendation": "Considerar política de expiração (90–365 dias)",
        })
    elif max_age > 365:
        settings.append({
            "name": "Validade Máxima", "value": f"{max_age} dias",
            "status": "warning", "recommendation": "Recomendado no máximo 365 dias",
        })
    else:
        settings.append({
            "name": "Validade Máxima", "value": f"{max_age} dias",
            "status": "ok", "recommendation": "",
        })

    # Histórico de passwords
    hist = raw.get("pwd_history_length", 0) or 0
    if hist < 5:
        status, rec = "critical", "Mínimo recomendado: 10 passwords anteriores"
    elif hist < 10:
        status, rec = "warning", "Recomendado aumentar para 10 ou mais"
    else:
        status, rec = "ok", ""
    settings.append({
        "name": "Histórico", "value": f"{hist} passwords",
        "status": status, "recommendation": rec,
    })

    # Limiar de bloqueio
    threshold = raw.get("lockout_threshold", 0) or 0
    if threshold == 0:
        settings.append({
            "name": "Bloqueio por Tentativas", "value": "Desativado",
            "status": "critical", "recommendation": "Ativar bloqueio (5–10 tentativas recomendado)",
        })
    elif threshold > 10:
        settings.append({
            "name": "Bloqueio por Tentativas", "value": f"{threshold} tentativas",
            "status": "warning", "recommendation": "Recomendado reduzir para 5–10 tentativas",
        })
    else:
        settings.append({
            "name": "Bloqueio por Tentativas", "value": f"{threshold} tentativas",
            "status": "ok", "recommendation": "",
        })

    # Duração do bloqueio
    lockout_min = raw.get("lockout_duration_minutes")
    if threshold > 0:
        if lockout_min == 0:
            settings.append({
                "name": "Duração do Bloqueio", "value": "Até desbloqueio manual",
                "status": "ok", "recommendation": "",
            })
        elif lockout_min is None or lockout_min < 15:
            settings.append({
                "name": "Duração do Bloqueio",
                "value": f"{lockout_min} min" if lockout_min is not None else "N/A",
                "status": "warning", "recommendation": "Recomendado mínimo 15 minutos",
            })
        else:
            settings.append({
                "name": "Duração do Bloqueio", "value": f"{lockout_min} min",
                "status": "ok", "recommendation": "",
            })

    # Severidade global
    statuses = [s["status"] for s in settings]
    if "critical" in statuses:
        global_sev = "critical"
    elif "warning" in statuses:
        global_sev = "warning"
    else:
        global_sev = "ok"

    return settings, global_sev


# ─── Queries LDAP ──────────────────────────────────────────────────────────────

def get_default_policy(conn: Connection) -> dict:
    """
    Lê a política de password predefinida do objeto de domínio.
    Avalia cada configuração contra boas práticas de segurança.
    """
    domain_attrs = [
        "minPwdLength", "maxPwdAge", "minPwdAge",
        "pwdHistoryLength", "pwdProperties",
        "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
    ]

    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=domain_attrs,
            size_limit=1,
            time_limit=10,
        )
        entries = conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro ao ler política de domínio: {e}")
        entries = []

    if not entries:
        return {
            "title":       "Política de Password Predefinida",
            "severity":    "warning",
            "description": "Não foi possível ler a política de password do domínio.",
            "count":       0,
            "count_label": "Política inacessível",
            "settings":    [],
        }

    entry = entries[0]
    pwd_props = int(get_attr(entry, "pwdProperties", 0) or 0)

    raw = {
        "min_pwd_length":         int(get_attr(entry, "minPwdLength", 0)         or 0),
        "max_pwd_age_days":       _large_int_to_days(get_attr(entry, "maxPwdAge", None)),
        "min_pwd_age_days":       _large_int_to_days(get_attr(entry, "minPwdAge", None)),
        "pwd_history_length":     int(get_attr(entry, "pwdHistoryLength", 0)      or 0),
        "complexity_enabled":     bool(pwd_props & 1),
        "lockout_threshold":      int(get_attr(entry, "lockoutThreshold", 0)      or 0),
        "lockout_duration_minutes":    _large_int_to_minutes(get_attr(entry, "lockoutDuration", None)),
        "lockout_observation_minutes": _large_int_to_minutes(get_attr(entry, "lockoutObservationWindow", None)),
    }

    settings, severity = _evaluate_settings(raw)
    weak_count = sum(1 for s in settings if s["status"] in ("critical", "warning"))

    return {
        "title":       "Política de Password Predefinida do Domínio",
        "severity":    severity,
        "description": (
            "Configurações da Default Domain Password Policy. Aplicada a todos os utilizadores "
            "que não têm uma Fine-Grained Password Policy (PSO) específica. "
            "Configurações fracas aumentam o risco de comprometimento por password spraying "
            "ou brute force."
        ),
        "count":       weak_count,
        "count_label": f"{weak_count} {'configuração' if weak_count == 1 else 'configurações'} {'fraca' if weak_count == 1 else 'fracas'}",
        "settings":    settings,
    }


def get_fine_grained_policies(conn: Connection) -> dict:
    """
    Lista Fine-Grained Password Policies (PSOs) configuradas no domínio.
    PSOs têm precedência sobre a política predefinida quando aplicadas a um utilizador/grupo.
    """
    psc_dn = f"CN=Password Settings Container,CN=System,{config.BASE_DN}"
    pso_attrs = [
        "cn", "msDS-PasswordSettingsPrecedence",
        "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge",
        "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
        "msDS-LockoutThreshold", "msDS-LockoutDuration",
        "msDS-PSOAppliesTo",
    ]

    psos = []
    try:
        conn.search(
            search_base=psc_dn,
            search_filter="(objectClass=msDS-PasswordSettings)",
            search_scope=SUBTREE,
            attributes=pso_attrs,
            size_limit=0,
            time_limit=15,
        )
        for entry in conn.entries:
            precedence = get_attr(entry, "msDS-PasswordSettingsPrecedence", "N/A")
            min_len    = get_attr(entry, "msDS-MinimumPasswordLength", "N/A")
            max_age    = _large_int_to_days(_multival(entry, "msDS-MaximumPasswordAge")[0] if _multival(entry, "msDS-MaximumPasswordAge") else None)
            history    = get_attr(entry, "msDS-PasswordHistoryLength", "N/A")
            complexity = get_attr(entry, "msDS-PasswordComplexityEnabled", None)
            threshold  = get_attr(entry, "msDS-LockoutThreshold", "N/A")
            applies_to = _multival(entry, "msDS-PSOAppliesTo")

            psos.append({
                "name":        get_attr(entry, "cn", "N/A"),
                "precedence":  precedence,
                "min_length":  min_len,
                "max_age_days": max_age if max_age is not None else "N/A",
                "history":     history,
                "complexity":  "Sim" if complexity is True or str(complexity).upper() == "TRUE" else "Não",
                "lockout":     threshold,
                "targets":     len(applies_to),
            })

        psos.sort(key=lambda p: int(p["precedence"]) if str(p["precedence"]).isdigit() else 999)

    except LDAPExceptionError as e:
        print(f"[AVISO] Erro ao ler PSOs (pode requerer permissões adicionais): {e}")

    severity = "info" if psos else "ok"

    return {
        "title":       "Fine-Grained Password Policies (PSOs)",
        "severity":    severity,
        "description": (
            "PSOs permitem aplicar políticas de password diferentes a grupos ou utilizadores "
            "específicos, sobrepondo-se à política predefinida. Útil para contas de serviço "
            "ou utilizadores privilegiados. Ordenadas por precedência (valor menor = maior prioridade)."
        ),
        "count":       len(psos),
        "count_label": f"{len(psos)} PSO{'s' if len(psos) != 1 else ''} configurada{'s' if len(psos) != 1 else ''}",
        "psos":        psos,
    }


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 7: Análise da Política de Password do Domínio...")

    checks = [
        get_default_policy(conn),
        get_fine_grained_policies(conn),
    ]

    for check in checks:
        icon = {"critical": "🔴", "warning": "🟡", "ok": "🟢", "info": "🔵"}.get(check["severity"], "⚪")
        print(f"  {icon} {check['title']}: {check.get('count_label', check['count'])}")

    return {
        "module_name": "Política de Password do Domínio",
        "checks":      checks,
    }
