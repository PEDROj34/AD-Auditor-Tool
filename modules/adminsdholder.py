"""
modules/adminsdholder.py — Módulo 10: AdminSDHolder e Contas adminCount Orphaned.

O processo SDProp corre a cada 60 minutos e aplica o ACL do objeto AdminSDHolder
a todas as contas com adminCount=1. Estas contas ficam com ACLs muito restritivos
que impedem operações normais de gestão (reset de password, modificação de atributos).

Risco — Persistência via adminCount Orphaned:
  Contas que já NÃO pertencem a grupos privilegiados mas mantêm adminCount=1
  retêm as proteções do SDProp. Um atacante pode:
    1. Adicionar uma conta a Domain Admins (adminCount=1 é automaticamente definido)
    2. Remover a conta do grupo (passa despercebido em auditorias de grupos)
    3. A conta mantém adminCount=1 e ACLs restritivos indefinidamente

Grupos protegidos pelo SDProp (per MS-ADTS):
  Domain Admins, Administrators, Schema Admins, Enterprise Admins,
  Account Operators, Server Operators, Backup Operators, Print Operators,
  Replicators, Group Policy Creator Owners, Domain Controllers, etc.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import get_attr, get_display_name
import config


_PROTECTED_GROUPS = [
    "Domain Admins",
    "Administrators",
    "Schema Admins",
    "Enterprise Admins",
    "Group Policy Creator Owners",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "Replicators",
    "Cert Publishers",
    "Domain Controllers",
    "Read-only Domain Controllers",
    "Enterprise Read-only Domain Controllers",
    "RAS and IAS Servers",
    "Pre-Windows 2000 Compatible Access",
]


def _get_privileged_dns(conn: Connection) -> set:
    """Devolve o conjunto de DNs que são membros diretos de grupos privilegiados."""
    members: set = set()

    for group_name in _PROTECTED_GROUPS:
        try:
            conn.search(
                search_base=config.BASE_DN,
                search_filter=f"(&(objectClass=group)(cn={group_name}))",
                search_scope=SUBTREE,
                attributes=["member"],
                size_limit=1,
                time_limit=10,
            )
            if conn.entries:
                raw = conn.entries[0].entry_attributes_as_dict.get("member", [])
                if isinstance(raw, str):
                    raw = [raw]
                for dn in raw:
                    if dn:
                        members.add(dn.lower())
        except LDAPExceptionError:
            continue

    return members


def get_orphaned_adminsdholder(conn: Connection) -> dict:
    """
    Encontra contas com adminCount=1 que NÃO pertencem a nenhum grupo privilegiado.
    Estas contas são 'orphaned' — retêm proteções do SDProp sem justificação.
    """
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter="(&(objectClass=user)(adminCount=1)(!(objectClass=computer)))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName", "displayName", "givenName", "sn", "cn",
                "distinguishedName", "userAccountControl",
            ],
            size_limit=0,
            time_limit=15,
        )
        all_entries = conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro ao pesquisar contas com adminCount=1: {e}")
        all_entries = []

    if not all_entries:
        return {
            "title":             "Contas com adminCount Orphaned (AdminSDHolder)",
            "severity":          "ok",
            "description": (
                "Nenhuma conta encontrada com adminCount=1. "
                "O SDProp não está a proteger contas além dos grupos privilegiados normais."
            ),
            "count":             0,
            "count_label":       "0 contas com adminCount=1",
            "accounts":          [],
            "total_admin_count": 0,
            "active_privileged": 0,
        }

    privileged_dns = _get_privileged_dns(conn)

    orphaned: list         = []
    active_privileged: int = 0

    for entry in all_entries:
        dn       = (get_attr(entry, "distinguishedName", "") or "").lower()
        uac      = int(get_attr(entry, "userAccountControl", 0) or 0)
        disabled = bool(uac & 0x2)
        sam      = get_attr(entry, "sAMAccountName", "N/A")
        name     = get_display_name(entry)

        if dn in privileged_dns:
            active_privileged += 1
        else:
            orphaned.append({
                "username": sam,
                "name":     name,
                "dn":       get_attr(entry, "distinguishedName", "N/A"),
                "disabled": disabled,
            })

    severity = "critical" if orphaned else "ok"
    total    = len(all_entries)

    return {
        "title":       "Contas com adminCount Orphaned (AdminSDHolder)",
        "severity":    severity,
        "description": (
            "O processo SDProp (a cada 60 min) aplica ACLs restritivos do AdminSDHolder "
            "a todas as contas com adminCount=1. Contas que já não pertencem a grupos "
            "privilegiados mas mantêm adminCount=1 são 'orphaned': ficam protegidas pelo "
            "SDProp sem justificação, impedindo gestão normal (reset de password, modificação). "
            "Podem também ser usadas para persistência: um atacante remove a conta do grupo "
            "privilegiado mas mantém adminCount=1 para preservar os ACLs restritivos."
        ),
        "count":             len(orphaned),
        "count_label":       f"{len(orphaned)} orphaned de {total} com adminCount=1",
        "accounts":          orphaned,
        "total_admin_count": total,
        "active_privileged": active_privileged,
    }


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 10: AdminSDHolder / Contas adminCount Orphaned...")

    check   = get_orphaned_adminsdholder(conn)
    icon    = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")
    total   = check.get("total_admin_count", 0)
    orphaned = check["count"]

    if total > 0:
        print(f"  {icon} {total} conta(s) com adminCount=1, {orphaned} orphaned")
    else:
        print(f"  {icon} Nenhuma conta com adminCount=1")

    return {
        "module_name": "AdminSDHolder / Orphaned adminCount",
        "checks":      [check],
    }
