"""
modules/kerberoasting.py — Módulo 4: Análise de SPNs (Kerberoasting Readiness).

O que é Kerberoasting:
  1. Qualquer utilizador autenticado no domínio pode pedir um TGS (Ticket
     Granting Service) para qualquer SPN registado no AD.
  2. O TGS é cifrado com o hash NTLM da password da conta de serviço.
  3. O atacante extrai o ticket e faz cracking offline (Hashcat/John).
  4. Se a password for fraca, o atacante obtém as credenciais em texto claro.

O que este módulo faz:
  - Query LDAP: filtrar utilizadores (não computadores) com SPNs definidos
  - Excluir contas de computador (terminam em $) — são alvo de diferentes ataques
  - Classificar por risco:
    * CRÍTICO: conta de serviço com privilégios elevados (membro de grupos admin)
    * ALTO: conta ativa com SPN e password antiga
    * MÉDIO: conta ativa com SPN

Nota: Contas de máquina (krbtgt, computer accounts) têm passwords longas
e aleatórias — praticamente imunes a cracking. O foco são contas de utilizador.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import (
    filetime_to_datetime, days_since, format_date, get_attr, get_display_name, has_uac_flag
)
import config


SPN_USER_ATTRIBUTES = [
    "sAMAccountName", "displayName", "givenName", "sn", "cn",
    "servicePrincipalName", "userAccountControl", "pwdLastSet",
    "lastLogonTimestamp", "memberOf", "distinguishedName", "mail",
]

# Grupos que tornam uma conta de serviço kerberoastable de risco crítico
HIGH_PRIVILEGE_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
}


def _is_high_privilege(member_of: list) -> bool:
    """Verifica se a conta pertence a algum grupo de alto privilégio."""
    if not member_of:
        return False
    if not isinstance(member_of, list):
        member_of = [member_of]
    for group_dn in member_of:
        group_dn_lower = str(group_dn).lower()
        if any(priv in group_dn_lower for priv in HIGH_PRIVILEGE_GROUPS):
            return True
    return False


def get_kerberoastable_users(conn: Connection) -> dict:
    """
    Identifica contas de utilizador com SPNs configurados.

    Filtro LDAP:
      - objectClass=user + objectCategory=person → apenas utilizadores
      - servicePrincipalName=* → tem pelo menos um SPN
      - !(sAMAccountName=krbtgt) → excluir conta especial do Kerberos
      - !(userAccountControl:...=2) → contas ativas apenas

    Contas de computador (que também têm SPNs) são automaticamente
    excluídas por objectCategory=person.
    """
    ldap_filter = (
        "(&"
        "(objectClass=user)"
        "(objectCategory=person)"
        "(servicePrincipalName=*)"
        "(!(sAMAccountName=krbtgt))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # não desativadas
        ")"
    )

    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=SPN_USER_ATTRIBUTES,
            size_limit=0,
            time_limit=30,
        )
        entries = conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro na query de SPNs: {e}")
        entries = []

    spn_users = []
    for entry in entries:
        pwd_last_set_ft = get_attr(entry, "pwdLastSet", None)
        pwd_last_set_dt = filetime_to_datetime(pwd_last_set_ft)
        pwd_age_days    = days_since(pwd_last_set_dt)

        llt_ft = get_attr(entry, "lastLogonTimestamp", None)
        llt_dt = filetime_to_datetime(llt_ft)

        member_of = entry.memberOf.values if hasattr(entry, "memberOf") else []
        is_high_priv = _is_high_privilege(member_of)

        # SPNs: pode ser string (único) ou lista
        spns_raw = entry.servicePrincipalName.values if hasattr(entry, "servicePrincipalName") else []
        if isinstance(spns_raw, str):
            spns_raw = [spns_raw]

        # Determinar risco individual
        if is_high_priv:
            risk = "critical"
        elif pwd_age_days and pwd_age_days > config.OLD_PASSWORD_DAYS:
            risk = "warning"
        else:
            risk = "info"  # Sempre é um achado — qualquer SPN de utilizador é potencial alvo

        spn_users.append({
            "username":       get_attr(entry, "sAMAccountName", "N/A"),
            "display_name":   get_display_name(entry),
            "spns":           list(spns_raw),
            "spn_count":      len(spns_raw),
            "pwd_last_set":   format_date(pwd_last_set_dt),
            "pwd_age_days":   pwd_age_days if pwd_age_days is not None else "N/A",
            "last_logon":     format_date(llt_dt),
            "is_high_priv":   is_high_priv,
            "risk":           risk,
        })

    # Ordenar: críticos primeiro, depois por idade de password
    spn_users.sort(
        key=lambda u: (
            0 if u["risk"] == "critical" else 1 if u["risk"] == "warning" else 2,
            -(u["pwd_age_days"] if isinstance(u["pwd_age_days"], int) else 0)
        )
    )

    severity = "ok"
    if spn_users:
        if any(u["risk"] == "critical" for u in spn_users):
            severity = "critical"
        else:
            severity = "warning"

    return {
        "title":       "Contas Vulneráveis a Kerberoasting (SPNs em Contas de Utilizador)",
        "severity":    severity,
        "description": (
            "Qualquer utilizador autenticado pode pedir TGS tickets para estas contas "
            "e tentar cracking offline das passwords. Contas com privilégios elevados "
            "ou passwords antigas são risco CRÍTICO."
        ),
        "count":    len(spn_users),
        "users":    spn_users,
        "columns":  ["Username", "SPNs", "Idade da Password", "Último Login", "Risco"],
    }


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 4: Análise de SPNs (Kerberoasting)...")

    check = get_kerberoastable_users(conn)
    icon = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")
    print(f"  {icon} {check['title']}: {check['count']} encontrado(s)")

    return {
        "module_name": "Análise de SPNs (Kerberoasting)",
        "checks":      [check],
    }
