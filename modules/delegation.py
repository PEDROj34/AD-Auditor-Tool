"""
modules/delegation.py — Módulo 5: Análise de Delegação Kerberos.

Tipos de delegação:
  1. Unconstrained Delegation (TRUSTED_FOR_DELEGATION, UAC 0x80000):
     - A conta pode receber TGTs completos de qualquer utilizador que se autentique
       nos seus serviços — um atacante que comprometa este servidor impersona qualquer
       conta do domínio, incluindo Domain Admins.
     - DCs legitimamente têm este flag (SERVER_TRUST_ACCOUNT) — são excluídos.

  2. Constrained Delegation (msDS-AllowedToDelegateTo definido):
     - A conta pode impersonar utilizadores apenas para serviços específicos.
     - Se Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION, UAC 0x1000000) estiver
       ativo, a conta pode impersonar QUALQUER utilizador — risco CRÍTICO.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import filetime_to_datetime, format_date, get_attr, get_display_name
import config

# Valores dos flags UAC relevantes (inteiro)
_FLAG_UNCONSTRAINED       = 0x80000    # TRUSTED_FOR_DELEGATION
_FLAG_PROTO_TRANSITION    = 0x1000000  # TRUSTED_TO_AUTH_FOR_DELEGATION
_FLAG_DC                  = 0x2000     # SERVER_TRUST_ACCOUNT (Domain Controllers)

_USER_ATTRS = [
    "sAMAccountName", "displayName", "givenName", "sn", "cn",
    "userAccountControl", "lastLogonTimestamp", "distinguishedName",
    "msDS-AllowedToDelegateTo",
]

_COMP_ATTRS = [
    "sAMAccountName", "dNSHostName",
    "userAccountControl", "lastLogonTimestamp", "distinguishedName",
    "msDS-AllowedToDelegateTo",
]


def _multival(entry, attr_name: str) -> list:
    """Lê atributos multi-valor com nomes hifenizados (ex: msDS-AllowedToDelegateTo)."""
    try:
        vals = entry.entry_attributes_as_dict.get(attr_name, [])
        if isinstance(vals, str):
            return [vals]
        return [v for v in vals if v] if vals else []
    except Exception:
        return []


def _get_unconstrained(conn: Connection) -> list:
    """
    Devolve utilizadores e computadores (sem DCs) com Unconstrained Delegation.

    Exclui DCs via flag SERVER_TRUST_ACCOUNT (0x2000) — estes legitimamente
    têm TRUSTED_FOR_DELEGATION e devem ser ignorados nesta análise.
    """
    queries = [
        (
            "(&(objectClass=user)(objectCategory=person)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"      # não desativadas
            "(userAccountControl:1.2.840.113556.1.4.803:=524288))",   # TRUSTED_FOR_DELEGATION
            _USER_ATTRS,
            "Utilizador",
        ),
        (
            "(&(objectClass=computer)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",  # excl. DCs
            _COMP_ATTRS,
            "Computador",
        ),
    ]

    accounts = []
    for ldap_filter, attrs, acct_type in queries:
        try:
            conn.search(
                search_base=config.BASE_DN,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=0,
                time_limit=30,
            )
            for entry in conn.entries:
                uac = int(get_attr(entry, "userAccountControl", 0) or 0)
                llt_dt = filetime_to_datetime(get_attr(entry, "lastLogonTimestamp", None))
                name = get_attr(entry, "sAMAccountName", "N/A")
                display = (
                    get_display_name(entry) if acct_type == "Utilizador"
                    else (get_attr(entry, "dNSHostName", None) or name)
                )
                accounts.append({
                    "username":            name,
                    "display_name":        display,
                    "account_type":        acct_type,
                    "protocol_transition": bool(uac & _FLAG_PROTO_TRANSITION),
                    "last_logon":          format_date(llt_dt),
                    "risk":                "critical",
                })
        except LDAPExceptionError as e:
            print(f"[AVISO] Erro na query unconstrained delegation ({acct_type}): {e}")

    return accounts


def _get_constrained(conn: Connection) -> list:
    """
    Devolve contas (utilizadores e computadores) com Constrained Delegation.

    Sinaliza como CRÍTICO se Protocol Transition estiver ativo — permite
    impersonar qualquer utilizador sem necessidade de autenticação Kerberos prévia.
    """
    queries = [
        (
            "(&(objectClass=user)(objectCategory=person)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(msDS-AllowedToDelegateTo=*))",
            _USER_ATTRS,
            "Utilizador",
        ),
        (
            "(&(objectClass=computer)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(msDS-AllowedToDelegateTo=*))",
            _COMP_ATTRS,
            "Computador",
        ),
    ]

    accounts = []
    for ldap_filter, attrs, acct_type in queries:
        try:
            conn.search(
                search_base=config.BASE_DN,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=0,
                time_limit=30,
            )
            for entry in conn.entries:
                uac = int(get_attr(entry, "userAccountControl", 0) or 0)
                proto_transition = bool(uac & _FLAG_PROTO_TRANSITION)
                targets = _multival(entry, "msDS-AllowedToDelegateTo")
                llt_dt = filetime_to_datetime(get_attr(entry, "lastLogonTimestamp", None))
                name = get_attr(entry, "sAMAccountName", "N/A")
                display = (
                    get_display_name(entry) if acct_type == "Utilizador"
                    else (get_attr(entry, "dNSHostName", None) or name)
                )
                accounts.append({
                    "username":            name,
                    "display_name":        display,
                    "account_type":        acct_type,
                    "allowed_targets":     targets,
                    "protocol_transition": proto_transition,
                    "last_logon":          format_date(llt_dt),
                    "risk":                "critical" if proto_transition else "warning",
                })
        except LDAPExceptionError as e:
            print(f"[AVISO] Erro na query constrained delegation ({acct_type}): {e}")

    accounts.sort(key=lambda a: (0 if a["risk"] == "critical" else 1, a["username"]))
    return accounts


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 5: Análise de Delegação Kerberos...")

    unconstrained = _get_unconstrained(conn)
    constrained   = _get_constrained(conn)

    sev_uncon = "critical" if unconstrained else "ok"
    sev_con = "ok"
    if constrained:
        sev_con = "critical" if any(a["protocol_transition"] for a in constrained) else "warning"

    checks = [
        {
            "title":       "Delegação Sem Restrições (Unconstrained Delegation)",
            "severity":    sev_uncon,
            "description": (
                "Contas com Unconstrained Delegation recebem TGTs completos de qualquer utilizador "
                "que se autentique nos seus serviços. Um atacante que comprometa um destes hosts "
                "pode impersonar qualquer conta do domínio, incluindo Domain Admins. "
                "DCs são excluídos desta lista (delegação legítima)."
            ),
            "count":    len(unconstrained),
            "accounts": unconstrained,
            "columns":  ["Username", "Tipo", "Último Login", "Risco"],
        },
        {
            "title":       "Delegação Restrita (Constrained Delegation)",
            "severity":    sev_con,
            "description": (
                "Contas com Constrained Delegation podem impersonar utilizadores apenas para serviços "
                "específicos. Se Protocol Transition estiver ativo, a conta pode impersonar QUALQUER "
                "utilizador sem autenticação Kerberos prévia — risco CRÍTICO independentemente dos "
                "serviços configurados."
            ),
            "count":    len(constrained),
            "accounts": constrained,
            "columns":  ["Username", "Tipo", "Serviços Permitidos", "Protocol Transition", "Risco"],
        },
    ]

    for check in checks:
        icon = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")
        print(f"  {icon} {check['title']}: {check['count']} encontrado(s)")

    return {
        "module_name": "Delegação Kerberos",
        "checks":      checks,
    }
