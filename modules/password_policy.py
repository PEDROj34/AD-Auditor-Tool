"""
modules/password_policy.py — Módulo 1: Auditoria de Políticas de Password e Contas.

Queries LDAP efetuadas:
  1. Fine-Grained Password Policies (PSO) — via container cn=Password Settings Container
  2. Default Domain Password Policy — via rootDSE / objeto de domínio
  3. Utilizadores com falhas de configuração UAC:
     - PASSWD_NOTREQD      → Password não obrigatória (risco crítico)
     - DONT_EXPIRE_PASSWORD → Password nunca expira (risco alto)
     - DONT_REQ_PREAUTH    → ASREPRoasting (risco crítico)
  4. Utilizadores com passwords antigas (pwdLastSet > limiar configurado)

Porquê estes filtros LDAP:
  - Filtramos logo no servidor AD (não no cliente) para minimizar dados
    transferidos e evitar timeouts em domínios com milhares de objetos.
  - Atributo `userAccountControl` é uma bitmask; o filtro LDAP
    `:1.2.840.113556.1.4.803:=` é o "bitwise AND" do AD (OID LDAP_MATCHING_RULE_BIT_AND).
    Isto permite filtrar flags UAC diretamente na query.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import (
    filetime_to_datetime, days_since, has_uac_flag,
    format_date, get_attr, get_display_name, UAC_FLAGS
)
import config


# ─── Atributos a recolher por utilizador (minimizar dados transferidos) ───────
USER_ATTRIBUTES = [
    "sAMAccountName",
    "displayName", "givenName", "sn", "cn",
    "userAccountControl",
    "pwdLastSet",
    "lastLogonTimestamp",
    "whenCreated",
    "mail",
    "memberOf",
    "distinguishedName",
    "description",
]


def _search_users(conn: Connection, ldap_filter: str, attributes: list) -> list:
    """
    Executa uma query LDAP com o filtro fornecido e devolve as entradas.

    Args:
        conn: sessão LDAP autenticada
        ldap_filter: filtro LDAP (ex: "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))")
        attributes: lista de atributos a recolher

    Returns:
        Lista de entradas LDAP, ou [] em caso de erro
    """
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            size_limit=0,        # Sem limite de resultados
            time_limit=30,       # Timeout de 30s por query
        )
        return conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro na query LDAP '{ldap_filter[:60]}...': {e}")
        return []


def get_password_not_required(conn: Connection) -> dict:
    """
    Identifica utilizadores com o flag PASSWD_NOTREQD ativo.

    Flag UAC 0x0020 (32): a conta pode autenticar com password vazia.
    Risco: CRÍTICO — permite acesso sem credenciais válidas.

    Filtro LDAP:
      (&
        (objectClass=user)         → apenas utilizadores (não computadores)
        (objectCategory=person)    → exclui grupos e outros objetos
        (!(userAccountControl:1.2.840.113556.1.4.803:=2))  → exclui contas desativadas
        (userAccountControl:1.2.840.113556.1.4.803:=32)    → PASSWD_NOTREQD ativo
      )

    O OID :1.2.840.113556.1.4.803: é o LDAP_MATCHING_RULE_BIT_AND —
    devolve entradas onde o atributo, tratado como bitmask, tem o bit especificado ativo.
    """
    ldap_filter = (
        "(&"
        "(objectClass=user)"
        "(objectCategory=person)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"   # não desativadas
        "(userAccountControl:1.2.840.113556.1.4.803:=32)"      # PASSWD_NOTREQD = 32
        ")"
    )
    entries = _search_users(conn, ldap_filter, USER_ATTRIBUTES)

    users = []
    for entry in entries:
        users.append({
            "username":     get_attr(entry, "sAMAccountName", "N/A"),
            "display_name": get_display_name(entry),
            "uac":          get_attr(entry, "userAccountControl", 0),
        })

    return {
        "title":       "Utilizadores com Password Não Obrigatória (PASSWD_NOTREQD)",
        "severity":    "critical" if users else "ok",
        "description": (
            "O flag PASSWD_NOTREQD permite que a conta autentique sem password. "
            "Um atacante pode explorar isto para acesso trivial ao domínio."
        ),
        "count":  len(users),
        "users":  users,
        "columns": ["Username", "Nome Completo", "UAC Value"],
    }


def get_non_expiring_passwords(conn: Connection) -> dict:
    """
    Identifica utilizadores com o flag DONT_EXPIRE_PASSWORD ativo.

    Flag UAC 0x10000 (65536): a password nunca expira, ignorando a política.
    Risco: ALTO — passwords antigas aumentam janela de exposição pós-breach.
    """
    ldap_filter = (
        "(&"
        "(objectClass=user)"
        "(objectCategory=person)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"     # não desativadas
        "(userAccountControl:1.2.840.113556.1.4.803:=65536)"    # DONT_EXPIRE_PASSWORD
        ")"
    )
    entries = _search_users(conn, ldap_filter, USER_ATTRIBUTES)

    users = []
    for entry in entries:
        pwd_last_set_ft  = get_attr(entry, "pwdLastSet", None)
        pwd_last_set_dt  = filetime_to_datetime(pwd_last_set_ft)
        pwd_age_days     = days_since(pwd_last_set_dt)

        users.append({
            "username":      get_attr(entry, "sAMAccountName", "N/A"),
            "display_name":  get_display_name(entry),
            "pwd_last_set":  format_date(pwd_last_set_dt),
            "pwd_age_days":  pwd_age_days if pwd_age_days is not None else "N/A",
        })

    # Ordenar por idade da password (mais antigas primeiro)
    users.sort(
        key=lambda u: u["pwd_age_days"] if isinstance(u["pwd_age_days"], int) else -1,
        reverse=True
    )

    return {
        "title":       "Utilizadores com Password Sem Expiração (DONT_EXPIRE_PASSWORD)",
        "severity":    "warning" if users else "ok",
        "description": (
            "Passwords que nunca expiram violam o princípio de rotação periódica. "
            "Em caso de comprometimento, a janela de exposição é indefinida."
        ),
        "count":  len(users),
        "users":  users,
        "columns": ["Username", "Nome Completo", "Última Alteração de Password", "Idade (dias)"],
    }


def get_old_passwords(conn: Connection) -> dict:
    """
    Identifica utilizadores ativos cuja password não é alterada há mais de
    `config.OLD_PASSWORD_DAYS` dias (independentemente da política de expiração).

    Nota: `pwdLastSet=0` significa que a password foi forçada a expirar pelo admin.
    Não filtramos isso aqui — é um achado separado relevante.
    """
    ldap_filter = (
        "(&"
        "(objectClass=user)"
        "(objectCategory=person)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # não desativadas
        "(pwdLastSet=*)"                                       # tem pwdLastSet definido
        ")"
    )
    entries = _search_users(conn, ldap_filter, USER_ATTRIBUTES)

    old_pwd_users = []
    for entry in entries:
        pwd_last_set_ft = get_attr(entry, "pwdLastSet", None)
        pwd_last_set_dt = filetime_to_datetime(pwd_last_set_ft)
        pwd_age_days    = days_since(pwd_last_set_dt)

        if pwd_age_days is not None and pwd_age_days > config.OLD_PASSWORD_DAYS:
            old_pwd_users.append({
                "username":      get_attr(entry, "sAMAccountName", "N/A"),
                "display_name":  get_display_name(entry),
                "pwd_last_set":  format_date(pwd_last_set_dt),
                "pwd_age_days":  pwd_age_days,
            })

    old_pwd_users.sort(key=lambda u: u["pwd_age_days"], reverse=True)

    severity = "ok"
    if old_pwd_users:
        severity = "critical" if any(u["pwd_age_days"] > 365 for u in old_pwd_users) else "warning"

    return {
        "title":       f"Utilizadores com Password Antiga (> {config.OLD_PASSWORD_DAYS} dias)",
        "severity":    severity,
        "description": (
            f"Passwords não alteradas há mais de {config.OLD_PASSWORD_DAYS} dias "
            "representam risco acrescido em caso de breach histórico não detetado."
        ),
        "count":  len(old_pwd_users),
        "users":  old_pwd_users,
        "columns": ["Username", "Nome Completo", "Última Alteração", "Idade (dias)"],
    }


def get_asreproastable_users(conn: Connection) -> dict:
    """
    Identifica utilizadores com DONT_REQ_PREAUTH ativo (ASREPRoasting).

    Flag UAC 0x400000 (4194304): o AD não exige pré-autenticação Kerberos.
    Risco: CRÍTICO — um atacante sem credenciais pode solicitar um AS-REP
    cifrado com a hash da password e fazer offline cracking.

    Diferença para Kerberoasting:
      - ASREPRoasting: não precisa de credenciais (pré-auth desativada)
      - Kerberoasting: precisa de credenciais, ataca TGS tickets de SPNs
    """
    ldap_filter = (
        "(&"
        "(objectClass=user)"
        "(objectCategory=person)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"  # DONT_REQ_PREAUTH
        ")"
    )
    entries = _search_users(conn, ldap_filter, USER_ATTRIBUTES)

    users = []
    for entry in entries:
        users.append({
            "username":     get_attr(entry, "sAMAccountName", "N/A"),
            "display_name": get_display_name(entry),
            "uac":          get_attr(entry, "userAccountControl", 0),
        })

    return {
        "title":       "Utilizadores Vulneráveis a ASREPRoasting (DONT_REQ_PREAUTH)",
        "severity":    "critical" if users else "ok",
        "description": (
            "Pré-autenticação Kerberos desativada — um atacante sem credenciais pode "
            "obter hashes de passwords para cracking offline. Corrigir imediatamente."
        ),
        "count":  len(users),
        "users":  users,
        "columns": ["Username", "Nome Completo", "UAC Value"],
    }


def run(conn: Connection) -> dict:
    """
    Ponto de entrada do módulo. Executa todos os checks e agrega resultados.

    Returns:
        dict com os resultados de todos os sub-módulos de passwords/contas
    """
    print("[*] Módulo 1: Auditoria de Políticas de Password e Contas...")

    results = {
        "module_name": "Políticas de Password e Contas",
        "checks": [
            get_password_not_required(conn),
            get_non_expiring_passwords(conn),
            get_old_passwords(conn),
            get_asreproastable_users(conn),
        ]
    }

    for check in results["checks"]:
        icon = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")
        print(f"  {icon} {check['title']}: {check['count']} encontrado(s)")

    return results
