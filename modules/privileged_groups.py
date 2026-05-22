"""
modules/privileged_groups.py — Módulo 3: Mapeamento de Grupos Privilegiados.

Estratégia de query:
  Para cada grupo crítico, usamos dois métodos complementares:
  1. Query direta ao grupo (member attribute) — membros diretos
  2. Filtro memberOf no utilizador com recursão via LDAP_MATCHING_RULE_IN_CHAIN
     (OID :1.2.840.113556.1.4.1941:) — apanha membros de grupos aninhados

  A recursão é importante porque o AD suporta nesting de grupos:
  Domain Admins pode conter "IT-Managers" que contém "jdoe" — sem recursão,
  jdoe não seria identificado como admin efetivo.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import filetime_to_datetime, format_date, get_attr, get_display_name, extract_cn
import config


GROUP_ATTRIBUTES = ["member", "distinguishedName", "description", "whenCreated"]

USER_ATTRIBUTES = [
    "sAMAccountName", "displayName", "givenName", "sn", "cn",
    "userAccountControl", "lastLogonTimestamp", "mail", "distinguishedName",
]


def _get_group_dn(conn: Connection, group_name: str) -> str | None:
    """Resolve o Distinguished Name de um grupo pelo seu nome."""
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter=f"(&(objectClass=group)(sAMAccountName={group_name}))",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            size_limit=1,
        )
        if conn.entries:
            return get_attr(conn.entries[0], "distinguishedName", None)
    except LDAPExceptionError:
        pass
    return None


def get_group_members(conn: Connection, group_name: str) -> dict:
    """
    Lista todos os membros efetivos (incluindo nested) de um grupo privilegiado.

    Usa LDAP_MATCHING_RULE_IN_CHAIN (:1.2.840.113556.1.4.1941:) para
    recursão automática em grupos aninhados — mais fiável que percorrer
    o atributo `member` manualmente nível a nível.

    Args:
        conn: sessão LDAP autenticada
        group_name: nome do grupo (ex: "Domain Admins")

    Returns:
        dict com informação do grupo e lista de membros
    """
    group_dn = _get_group_dn(conn, group_name)

    if not group_dn:
        return {
            "group_name": group_name,
            "severity":   "ok",
            "description": f"Grupo '{group_name}' não encontrado no domínio.",
            "count":   0,
            "members": [],
            "columns": ["Username", "Nome Completo", "Estado", "Último Login", "Email"],
        }

    # Filtro com IN_CHAIN para recursão em grupos aninhados
    ldap_filter = (
        f"(&"
        f"(objectClass=user)"
        f"(memberOf:1.2.840.113556.1.4.1941:={group_dn})"
        f")"
    )

    members = []
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=USER_ATTRIBUTES,
            size_limit=0,
            time_limit=30,
        )

        for entry in conn.entries:
            uac    = get_attr(entry, "userAccountControl", 0)
            is_disabled = bool(int(uac or 0) & 0x0002)
            llt_ft = get_attr(entry, "lastLogonTimestamp", None)
            llt_dt = filetime_to_datetime(llt_ft)

            members.append({
                "username":     get_attr(entry, "sAMAccountName", "N/A"),
                "display_name": get_display_name(entry),
                "status":       "Desativada" if is_disabled else "Ativa",
                "last_logon":   format_date(llt_dt),
                "mail":         get_attr(entry, "mail", "N/A"),
                "is_disabled":  is_disabled,
            })

    except LDAPExceptionError as e:
        print(f"[AVISO] Erro ao listar membros de '{group_name}': {e}")

    members.sort(key=lambda m: (m["is_disabled"], m["username"]))

    # Severidade: qualquer conta desativada num grupo privilegiado é crítico
    has_disabled = any(m["is_disabled"] for m in members)
    severity = "ok"
    if members:
        severity = "critical" if has_disabled else "warning"
    # Schema Admins e Enterprise Admins devem ter 0 membros em operação normal
    if group_name in ("Schema Admins", "Enterprise Admins") and len(members) > 0:
        severity = "critical"

    return {
        "group_name":  group_name,
        "severity":    severity,
        "description": _get_group_description(group_name),
        "count":       len(members),
        "members":     members,
        "columns":     ["Username", "Nome Completo", "Estado", "Último Login", "Email"],
    }


def _get_group_description(group_name: str) -> str:
    """Descrição de risco para cada grupo crítico — útil para o relatório."""
    descriptions = {
        "Domain Admins": (
            "Controlo total sobre o domínio AD. Cada membro é um alvo de alto valor "
            "para atacantes. Deve ter o menor número possível de contas (idealmente < 5)."
        ),
        "Enterprise Admins": (
            "Privilégios sobre toda a forest AD. Deve estar VAZIO em operação normal — "
            "apenas povoado temporariamente durante tarefas de gestão específicas."
        ),
        "Schema Admins": (
            "Pode modificar o schema do AD — alterações irreversíveis. "
            "Deve estar VAZIO em operação normal."
        ),
        "Administrators": (
            "Administradores locais em todos os DCs. Membros têm acesso privilegiado "
            "a controladores de domínio. Rever frequentemente."
        ),
        "Account Operators": (
            "Pode criar, modificar e eliminar contas e grupos (exceto grupos protegidos). "
            "Privilégios frequentemente esquecidos — risco de escalada."
        ),
        "Backup Operators": (
            "Pode fazer backup/restore de ficheiros ignorando ACLs, e fazer logon local "
            "em DCs. Frequentemente subestimado — equivale quase a Domain Admin."
        ),
        "Group Policy Creator Owners": (
            "Pode criar GPOs e aplicar políticas a toda a organização. "
            "Vetor comum de persistência e escalada de privilégios."
        ),
    }
    return descriptions.get(group_name, f"Grupo privilegiado: {group_name}")


def _discover_privileged_groups(conn: Connection) -> list[str]:
    """
    Auto-descobre grupos privilegiados via adminCount=1.

    O processo SDProp define adminCount=1 em todos os grupos que protege —
    built-ins (Domain Admins, etc.) e grupos personalizados aninhados em
    grupos protegidos. Independente do idioma do servidor.

    Fallback para config.PRIVILEGED_GROUPS se a query falhar ou retornar vazio.
    """
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter="(&(objectClass=group)(adminCount=1))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "cn"],
            size_limit=0,
            time_limit=15,
        )
        names = []
        for entry in conn.entries:
            sam  = get_attr(entry, "sAMAccountName", None)
            cn   = get_attr(entry, "cn", None)
            name = str(sam or cn or "").strip()
            if name:
                names.append(name)
        if names:
            return sorted(names)
    except LDAPExceptionError as e:
        print(f"  [!] Erro ao descobrir grupos via adminCount: {e}")

    print("  [!] Fallback: usando lista de grupos do config.py")
    return list(config.PRIVILEGED_GROUPS)


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 3: Mapeamento de Grupos Privilegiados...")

    group_names = _discover_privileged_groups(conn)
    print(f"  [→] {len(group_names)} grupos privilegiados identificados")

    checks = []
    for group_name in group_names:
        result = get_group_members(conn, group_name)
        checks.append(result)
        icon = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(result["severity"], "⚪")
        print(f"  {icon} {group_name}: {result['count']} membro(s)")

    return {
        "module_name": "Grupos Privilegiados",
        "checks":      checks,
    }
