"""
modules/inactive_accounts.py — Módulo 2: Contas Órfãs e Inativas.

Queries LDAP:
  1. Utilizadores sem login há mais de 90 dias (lastLogonTimestamp)
  2. Computadores sem login há mais de 90 dias
  3. Contas desativadas que ainda existem no AD

Nota sobre lastLogonTimestamp vs lastLogon:
  - lastLogon: atualizado em cada DC mas NÃO replicado entre DCs (impreciso)
  - lastLogonTimestamp: replicado entre DCs, mas atualizado com tolerância de
    14 dias (para reduzir tráfego de replicação) — suficiente para auditoria
  Esta ferramenta usa lastLogonTimestamp por ser o único atributo fiável
  a partir de um único DC.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import filetime_to_datetime, days_since, format_date, get_attr, get_display_name
import config


USER_ATTRIBUTES = [
    "sAMAccountName", "displayName", "givenName", "sn", "cn",
    "userAccountControl", "lastLogonTimestamp", "whenCreated", "mail", "distinguishedName",
]

COMPUTER_ATTRIBUTES = [
    "sAMAccountName", "dNSHostName", "operatingSystem",
    "lastLogonTimestamp", "whenCreated", "distinguishedName",
]


def _search(conn: Connection, ldap_filter: str, attributes: list) -> list:
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            size_limit=0,
            time_limit=30,
        )
        return conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro na query de contas inativas: {e}")
        return []


def get_inactive_users(conn: Connection) -> dict:
    """
    Utilizadores ativos sem autenticação há mais de `INACTIVE_DAYS` dias.

    Filtro: utilizadores ativos (não desativados) com lastLogonTimestamp
    definido. O cálculo de "inativo" é feito no cliente Python após recolha,
    pois o FILETIME não é diretamente comparável via filtro LDAP simples.

    Para domínios grandes (>10k utilizadores), considerar filtro LDAP com
    comparação de timestamp direta usando o formato FILETIME calculado.
    """
    inactive = []
    never_logged = []

    all_filter = (
        "(&(objectClass=user)(objectCategory=person)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    all_entries = _search(conn, all_filter, USER_ATTRIBUTES)

    for entry in all_entries:
        llt_ft = get_attr(entry, "lastLogonTimestamp", None)
        llt_dt = filetime_to_datetime(llt_ft)
        days   = days_since(llt_dt)

        record = {
            "username":      get_attr(entry, "sAMAccountName", "N/A"),
            "display_name":  get_display_name(entry),
            "last_logon":    format_date(llt_dt),
            "inactive_days": days if days is not None else "Nunca",
        }

        if llt_dt is None:
            never_logged.append(record)
        elif days > config.INACTIVE_DAYS:
            inactive.append(record)

    inactive.sort(
        key=lambda u: u["inactive_days"] if isinstance(u["inactive_days"], int) else 999999,
        reverse=True
    )

    all_inactive = inactive + never_logged
    severity = "ok"
    if all_inactive:
        severity = "critical" if len(all_inactive) > 10 else "warning"

    return {
        "title":       f"Utilizadores Inativos (sem login há > {config.INACTIVE_DAYS} dias)",
        "severity":    severity,
        "description": (
            "Contas inativas são vetores de ataque frequentes — passwords antigas, "
            "sem monitorização, e potencialmente com privilégios desnecessários mantidos."
        ),
        "count":   len(all_inactive),
        "users":   all_inactive,
        "columns": ["Username", "Nome Completo", "Último Login", "Dias Inativo"],
    }


def get_inactive_computers(conn: Connection) -> dict:
    """
    Computadores sem autenticação no domínio há mais de `INACTIVE_DAYS` dias.

    Máquinas inativas podem indicar:
      - Equipamento abandonado com contas de domínio ativas
      - Risco de lateral movement para máquinas sem patches
    """
    ldap_filter = (
        "(&"
        "(objectClass=computer)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # não desativadas
        ")"
    )
    entries = _search(conn, ldap_filter, COMPUTER_ATTRIBUTES)

    inactive = []
    for entry in entries:
        llt_ft = get_attr(entry, "lastLogonTimestamp", None)
        llt_dt = filetime_to_datetime(llt_ft)
        days   = days_since(llt_dt)

        if days is None or days > config.INACTIVE_DAYS:
            inactive.append({
                "hostname":      get_attr(entry, "sAMAccountName", "N/A").rstrip("$"),
                "dns_name":      get_attr(entry, "dNSHostName", "N/A"),
                "os":            get_attr(entry, "operatingSystem", "N/A"),
                "last_logon":    format_date(llt_dt),
                "inactive_days": days if days is not None else "Nunca",
            })

    inactive.sort(
        key=lambda c: c["inactive_days"] if isinstance(c["inactive_days"], int) else 999999,
        reverse=True
    )

    return {
        "title":       f"Computadores Inativos (sem login há > {config.INACTIVE_DAYS} dias)",
        "severity":    "warning" if inactive else "ok",
        "description": (
            "Contas de computador inativas representam superfície de ataque não monitorizada. "
            "Máquinas sem login regular podem não estar a receber políticas de segurança."
        ),
        "count":     len(inactive),
        "computers": inactive,
        "columns":   ["Hostname", "DNS", "Sistema Operativo", "Último Login", "Dias Inativo"],
    }


def get_disabled_accounts(conn: Connection) -> dict:
    """
    Lista contas desativadas que ainda existem no AD.

    Contas desativadas mas não removidas acumulam privilégios históricos
    e podem ser reativadas por um atacante com acesso suficiente.
    """
    ldap_filter = (
        "(&"
        "(objectClass=user)"
        "(objectCategory=person)"
        "(userAccountControl:1.2.840.113556.1.4.803:=2)"  # ACCOUNTDISABLE ativo
        ")"
    )
    entries = _search(conn, ldap_filter, USER_ATTRIBUTES)

    users = []
    for entry in entries:
        llt_ft = get_attr(entry, "lastLogonTimestamp", None)
        llt_dt = filetime_to_datetime(llt_ft)
        users.append({
            "username":     get_attr(entry, "sAMAccountName", "N/A"),
            "display_name": get_display_name(entry),
            "last_logon":   format_date(llt_dt),
        })

    return {
        "title":       "Contas Desativadas Presentes no AD",
        "severity":    "warning" if len(users) > 20 else "ok",
        "description": (
            "Contas desativadas devem ser revistas periodicamente e removidas "
            "quando já não são necessárias. Reduz a superfície de ataque e simplifica auditorias."
        ),
        "count":   len(users),
        "users":   users,
        "columns": ["Username", "Nome Completo", "Último Login"],
    }


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 2: Identificação de Contas Órfãs/Inativas...")

    results = {
        "module_name": "Contas Órfãs e Inativas",
        "checks": [
            get_inactive_users(conn),
            get_inactive_computers(conn),
            get_disabled_accounts(conn),
        ]
    }

    for check in results["checks"]:
        icon = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")
        count = check.get("count", 0)
        print(f"  {icon} {check['title']}: {count} encontrado(s)")

    return results
