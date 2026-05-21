"""
modules/domain_trusts.py — Módulo 9: Relações de Confiança do Domínio.

Domain trusts permitem que utilizadores de um domínio acedam a recursos noutro.

Riscos principais:
  - Trusts bidirecionais aumentam a superfície de ataque: comprometer um domínio
    pode facilitar o movimento lateral para domínios confiantes.
  - SID Filtering desativado (bit QUARANTINE_DOMAIN ausente em trustAttributes)
    permite SID History attacks: um atacante com controlo num domínio confiado
    pode injetar SIDs de grupos privilegiados do domínio confiante em tokens.
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import get_attr
import config


_TRUST_TYPE = {
    1: "Downlevel (NT)",
    2: "Active Directory",
    3: "MIT Kerberos",
    4: "DCE",
}

_TRUST_DIRECTION = {
    1: "Inbound (eles confiam em nós)",
    2: "Outbound (nós confiamos neles)",
    3: "Bidirecional",
}

# trustAttributes bitmask (MS-ADTS)
_ATTR_NON_TRANSITIVE    = 0x1
_ATTR_UPLEVEL_ONLY      = 0x2
_ATTR_QUARANTINED       = 0x4   # SID Filtering ativo
_ATTR_FOREST_TRANSITIVE = 0x8
_ATTR_CROSS_ORG         = 0x10
_ATTR_WITHIN_FOREST     = 0x20
_ATTR_TREAT_AS_EXTERNAL = 0x40
_ATTR_MIT_KERBEROS      = 0x80


def _parse_flags(attrs: int) -> list[str]:
    flags = []
    if attrs & _ATTR_NON_TRANSITIVE:    flags.append("Não transitivo")
    if attrs & _ATTR_FOREST_TRANSITIVE: flags.append("Forest trust")
    if attrs & _ATTR_WITHIN_FOREST:     flags.append("Dentro da forest")
    if attrs & _ATTR_CROSS_ORG:         flags.append("Cross-org")
    if attrs & _ATTR_TREAT_AS_EXTERNAL: flags.append("Externo")
    if attrs & _ATTR_MIT_KERBEROS:      flags.append("MIT Kerberos")
    return flags


def get_domain_trusts(conn: Connection) -> dict:
    """Queries trusted domain objects in CN=System."""
    system_dn = f"CN=System,{config.BASE_DN}"

    try:
        conn.search(
            search_base=system_dn,
            search_filter="(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=[
                "cn", "trustType", "trustDirection", "trustAttributes", "flatName",
            ],
            size_limit=0,
            time_limit=15,
        )
        entries = conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro ao ler domain trusts: {e}")
        entries = []

    trusts = []
    risky_count = 0

    for entry in entries:
        trust_type  = int(get_attr(entry, "trustType",       0) or 0)
        trust_dir   = int(get_attr(entry, "trustDirection",  0) or 0)
        trust_attrs = int(get_attr(entry, "trustAttributes", 0) or 0)

        sid_filtering = bool(trust_attrs & _ATTR_QUARANTINED)
        flags = _parse_flags(trust_attrs)

        # Risco: trust que nos faz confiar em domínio externo sem SID filtering
        is_outbound = trust_dir in (2, 3)
        is_risky    = is_outbound and not sid_filtering

        if is_risky:
            risky_count += 1

        trusts.append({
            "name":          get_attr(entry, "cn", "N/A"),
            "flat_name":     get_attr(entry, "flatName", "N/A"),
            "trust_type":    _TRUST_TYPE.get(trust_type, f"Tipo {trust_type}"),
            "direction":     _TRUST_DIRECTION.get(trust_dir, f"Direção {trust_dir}"),
            "sid_filtering": sid_filtering,
            "flags":         flags,
            "risky":         is_risky,
        })

    if not trusts:
        severity    = "ok"
        count_label = "Sem relações de confiança"
    elif risky_count > 0:
        severity    = "warning"
        count_label = f"{len(trusts)} trust{'s' if len(trusts) != 1 else ''}, {risky_count} sem SID filtering"
    else:
        severity    = "ok"
        count_label = f"{len(trusts)} trust{'s' if len(trusts) != 1 else ''} (SID filtering ativo)"

    return {
        "title":       "Relações de Confiança do Domínio (Trusts)",
        "severity":    severity,
        "description": (
            "Domain trusts permitem que utilizadores de um domínio acedam a recursos noutro. "
            "Trusts sem SID filtering (QUARANTINE_DOMAIN) são vulneráveis a SID History attacks: "
            "um atacante com controlo no domínio confiado pode forjar SIDs de grupos privilegiados "
            "do domínio confiante. Trusts bidirecionais duplicam a superfície de ataque."
        ),
        "count":       len(trusts),
        "count_label": count_label,
        "trusts":      trusts,
    }


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 9: Análise de Domain Trusts...")

    check = get_domain_trusts(conn)
    icon  = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")
    print(f"  {icon} {check['title']}: {check['count_label']}")

    return {
        "module_name": "Domain Trusts",
        "checks":      [check],
    }
