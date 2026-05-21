"""
modules/os_inventory.py — Módulo 8: Inventário de Sistemas Operativos e EOL.

Sistemas em fim de vida (EOL) não recebem patches de segurança e são alvos
preferenciais para exploits públicos (EternalBlue, PrintNightmare, etc.).

Classificação:
  EOL    — Windows XP, Vista, 7, Server 2003/2008 (inclui R2) — sem suporte
  Legacy — Windows 8.1, Server 2012 (inclui R2) — suporte terminado em 2023
  Atual  — Windows 10/11, Server 2016/2019/2022
"""

from ldap3 import Connection, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from core.utils import get_attr, filetime_to_datetime, format_date
import config


def _classify_os(os_name: str) -> str:
    """Classifica o SO como 'eol', 'legacy', ou 'current'."""
    if not os_name:
        return "unknown"
    os_lower = os_name.lower()

    eol_keywords = [
        "windows xp", "windows vista", "windows 7",
        "server 2003", "server 2008",
        "windows 8 ", "windows 8\t", "windows 8\"",
        "server 2011",
    ]
    for kw in eol_keywords:
        if kw in os_lower + " ":
            return "eol"

    # Windows 8 sem ".1"
    if "windows 8" in os_lower and "8.1" not in os_lower:
        return "eol"

    legacy_keywords = ["windows 8.1", "server 2012"]
    for kw in legacy_keywords:
        if kw in os_lower:
            return "legacy"

    return "current"


def get_os_inventory(conn: Connection) -> dict:
    """Queries computer objects and audits OS versions for EOL/legacy systems."""
    try:
        conn.search(
            search_base=config.BASE_DN,
            search_filter="(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=[
                "cn", "operatingSystem", "operatingSystemVersion",
                "lastLogonTimestamp", "userAccountControl",
            ],
            size_limit=0,
            time_limit=30,
        )
        entries = conn.entries
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro ao inventariar sistemas operativos: {e}")
        entries = []

    computers = []
    eol_count    = 0
    legacy_count = 0
    os_summary: dict = {}

    for entry in entries:
        uac      = int(get_attr(entry, "userAccountControl", 0) or 0)
        disabled = bool(uac & 0x2)
        os_name  = get_attr(entry, "operatingSystem", None)
        os_ver   = get_attr(entry, "operatingSystemVersion", None)
        llt_dt   = filetime_to_datetime(get_attr(entry, "lastLogonTimestamp", None))
        status   = _classify_os(os_name or "")

        if status == "eol":
            eol_count += 1
        elif status == "legacy":
            legacy_count += 1

        os_key = os_name or "Desconhecido"
        if os_key not in os_summary:
            os_summary[os_key] = {"count": 0, "status": status}
        os_summary[os_key]["count"] += 1

        computers.append({
            "name":       get_attr(entry, "cn", "N/A"),
            "os":         os_name or "Desconhecido",
            "os_version": os_ver or "N/A",
            "last_logon": format_date(llt_dt),
            "disabled":   disabled,
            "status":     status,
        })

    status_order = {"eol": 0, "legacy": 1, "current": 2, "unknown": 3}
    computers.sort(key=lambda c: (status_order.get(c["status"], 3), c["name"]))

    total = len(computers)
    current_count = total - eol_count - legacy_count

    if eol_count > 0:
        severity = "critical"
    elif legacy_count > 0:
        severity = "warning"
    elif total == 0:
        severity = "warning"
    else:
        severity = "ok"

    os_list = [
        {"os": k, "count": v["count"], "status": v["status"]}
        for k, v in os_summary.items()
    ]
    os_list.sort(key=lambda x: (-x["count"], x["os"]))

    return {
        "title":       "Inventário de Sistemas Operativos",
        "severity":    severity,
        "description": (
            "Sistemas com SO em fim de vida (EOL) não recebem patches de segurança, "
            "tornando-os alvos fáceis para exploits públicos (EternalBlue, PrintNightmare, etc.). "
            f"Detetados: {eol_count} EOL, {legacy_count} legacy, {current_count} atuais."
        ),
        "count":       eol_count + legacy_count,
        "count_label": f"{eol_count} EOL, {legacy_count} legacy de {total} total",
        "computers":   computers,
        "os_summary":  os_list,
        "total":       total,
    }


def run(conn: Connection) -> dict:
    """Ponto de entrada do módulo."""
    print("[*] Módulo 8: Inventário de Sistemas Operativos / EOL...")

    check = get_os_inventory(conn)
    icon  = {"critical": "🔴", "warning": "🟡", "ok": "🟢"}.get(check["severity"], "⚪")
    print(f"  {icon} Computadores: {check['total']} total — {check['count_label']}")

    return {
        "module_name": "Inventário SO / Sistemas EOL",
        "checks":      [check],
    }
