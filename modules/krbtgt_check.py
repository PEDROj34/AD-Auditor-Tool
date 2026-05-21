"""
modules/krbtgt_check.py — Módulo 6: Auditoria da Conta krbtgt (Golden Ticket Readiness).

A conta krbtgt é o Key Distribution Center (KDC) do Kerberos no Active Directory.
O seu hash NTLM é usado para cifrar e assinar todos os TGTs (Ticket Granting Tickets).

Risco principal — Golden Ticket:
  Se um atacante obtiver o hash da krbtgt (via DCSync, ntds.dit dump, etc.),
  pode forjar TGTs arbitrários com qualquer SID e qualquer privilégio.
  Estes tickets são válidos até a password ser rotacionada DUAS vezes.
  A Microsoft recomenda rotação a cada 180 dias, ou imediatamente após
  suspeita de comprometimento.

Nota: A conta krbtgt está sempre desativada no AD — é intencional e não é um finding.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import filetime_to_datetime, days_since, format_date, get_attr
import config


def get_krbtgt_info(conn: Connection) -> dict:
    """
    Audita a conta krbtgt — foca-se na idade da password como indicador
    de exposição a Golden Tickets históricos.
    """
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter="(&(objectClass=user)(sAMAccountName=krbtgt))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName", "pwdLastSet", "lastLogonTimestamp",
                "userAccountControl", "distinguishedName",
            ],
            size_limit=1,
            time_limit=10,
        )
        entries = conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro na query da conta krbtgt: {e}")
        entries = []

    if not entries:
        return {
            "title":       "Idade da Password da Conta krbtgt",
            "severity":    "warning",
            "description": (
                "A conta krbtgt não foi encontrada ou não é acessível via LDAP. "
                "Verifica se a conta existe e se o utilizador tem permissões de leitura."
            ),
            "count":       0,
            "count_label": "Não encontrada",
            "krbtgt":      None,
        }

    entry = entries[0]
    pwd_ft  = get_attr(entry, "pwdLastSet", None)
    pwd_dt  = filetime_to_datetime(pwd_ft)
    pwd_age = days_since(pwd_dt)
    llt_dt  = filetime_to_datetime(get_attr(entry, "lastLogonTimestamp", None))

    if pwd_age is None:
        severity    = "critical"
        risk_label  = "CRÍTICO — data desconhecida"
    elif pwd_age > 365:
        severity    = "critical"
        risk_label  = f"CRÍTICO — {pwd_age} dias"
    elif pwd_age > 180:
        severity    = "warning"
        risk_label  = f"AVISO — {pwd_age} dias"
    else:
        severity    = "ok"
        risk_label  = f"OK — {pwd_age} dias"

    age_display = pwd_age if pwd_age is not None else "N/A"

    return {
        "title":       "Idade da Password da Conta krbtgt",
        "severity":    severity,
        "description": (
            "A password da krbtgt é usada para cifrar todos os TGTs do domínio. "
            "Se comprometida (DCSync, ntds.dit dump), um atacante pode forjar Golden Tickets "
            "com qualquer privilégio. A Microsoft recomenda rotação a cada 180 dias. "
            "Após comprometimento confirmado, a password deve ser rotacionada DUAS vezes."
        ),
        "count":       1,
        "count_label": f"Password com {age_display} dias",
        "krbtgt": {
            "username":     "krbtgt",
            "pwd_last_set": format_date(pwd_dt),
            "pwd_age_days": age_display,
            "last_logon":   format_date(llt_dt),
            "risk_label":   risk_label,
        },
    }


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 6: Auditoria da Conta krbtgt...")

    check = get_krbtgt_info(conn)
    icon  = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")

    if check["krbtgt"]:
        age = check["krbtgt"]["pwd_age_days"]
        age_str = f"{age} dias" if isinstance(age, int) else "idade desconhecida (pwdLastSet=0)"
        print(f"  {icon} krbtgt: password com {age_str} sem rotação")
    else:
        print(f"  {icon} krbtgt: conta não encontrada")

    return {
        "module_name": "Conta krbtgt (Golden Ticket Readiness)",
        "checks":      [check],
    }
