"""
reporter/html_report.py — Geração do relatório HTML autónomo.

Produz um ficheiro HTML standalone (sem dependências externas) com:
  - Dashboard de sumário com contagem de findings por severidade
  - Secção por módulo com tabelas de resultados
  - Código de cores: Verde (OK), Laranja (Aviso), Vermelho (Crítico)
  - CSS embutido — ficheiro único, partilhável sem servidor web

Design: terminal/security aesthetic — dark theme profissional.
"""

import json
from datetime import datetime, timezone
import config


SEVERITY_CONFIG = {
    "critical": {"label": "CRÍTICO",  "color": "#ef4444", "bg": "#2d0a0a", "icon": "🔴"},
    "warning":  {"label": "AVISO",    "color": "#f97316", "bg": "#2d1500", "icon": "🟡"},
    "ok":       {"label": "OK",       "color": "#22c55e", "bg": "#0a2d0a", "icon": "🟢"},
    "info":     {"label": "INFO",     "color": "#3b82f6", "bg": "#0a1a2d", "icon": "🔵"},
}


def _get_css() -> str:
    return """
    :root {
        --bg-primary:   #0d0d0d;
        --bg-secondary: #141414;
        --bg-card:      #1a1a1a;
        --bg-table-alt: #111111;
        --border:       #2a2a2a;
        --border-soft:  #1a1a1a;
        --text-primary: #e8e8e8;
        --text-muted:   #888;
        --accent:       #00d4ff;
        --font-mono:    'Courier New', 'Lucida Console', monospace;
        --font-sans:    'Segoe UI', system-ui, sans-serif;
        --radius:       6px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; overflow: hidden; }
    body {
        background: var(--bg-primary);
        color: var(--text-primary);
        font-family: var(--font-sans);
        font-size: 14px;
        line-height: 1.6;
    }

    /* ── Layout ── */
    .layout { display: flex; height: 100vh; }

    /* ── Sidebar ── */
    .sidebar {
        width: 236px;
        min-width: 236px;
        background: #080808;
        border-right: 1px solid var(--border-soft);
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }
    .sidebar-brand {
        padding: 18px 16px 14px;
        border-bottom: 1px solid var(--border-soft);
        position: relative;
    }
    .sidebar-brand::after {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 2px;
        background: linear-gradient(90deg, var(--accent), transparent);
    }
    .brand-label {
        font-family: var(--font-mono);
        font-size: 9px;
        color: var(--accent);
        letter-spacing: 2px;
        margin-bottom: 5px;
    }
    .brand-domain { font-size: 14px; font-weight: 700; color: #fff; }
    .brand-meta {
        font-family: var(--font-mono);
        font-size: 10px;
        color: #333;
        margin-top: 3px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    /* ── Sidebar stats ── */
    .sidebar-stats {
        display: flex;
        padding: 10px;
        gap: 6px;
        border-bottom: 1px solid var(--border-soft);
    }
    .stat {
        flex: 1;
        text-align: center;
        padding: 8px 4px;
        border-radius: 4px;
        background: #0e0e0e;
        border: 1px solid transparent;
    }
    .stat.critical { border-color: rgba(239,68,68,0.18); }
    .stat.warning  { border-color: rgba(249,115,22,0.18); }
    .stat.ok       { border-color: rgba(34,197,94,0.15); }
    .stat-num {
        display: block;
        font-family: var(--font-mono);
        font-size: 20px;
        font-weight: 700;
        line-height: 1;
        margin-bottom: 2px;
    }
    .stat-label { font-size: 9px; color: #444; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat.critical .stat-num { color: #ef4444; }
    .stat.warning  .stat-num { color: #f97316; }
    .stat.ok       .stat-num { color: #22c55e; }

    /* ── Sidebar nav ── */
    .sidebar-nav {
        flex: 1;
        overflow-y: auto;
        padding: 6px 0;
        scrollbar-width: thin;
        scrollbar-color: #1e1e1e transparent;
    }
    .sidebar-nav::-webkit-scrollbar { width: 3px; }
    .sidebar-nav::-webkit-scrollbar-thumb { background: #1e1e1e; border-radius: 2px; }

    .nav-section-label {
        font-family: var(--font-mono);
        font-size: 9px;
        color: #2e2e2e;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        padding: 10px 16px 3px;
    }
    .nav-item {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 7px 16px;
        cursor: pointer;
        border-left: 2px solid transparent;
        transition: background 0.1s;
        color: #555;
        user-select: none;
    }
    .nav-item:hover { background: #0f0f0f; color: #999; }
    .nav-item.active {
        background: rgba(0,212,255,0.05);
        border-left-color: var(--accent);
        color: #ddd;
    }
    .nav-item.is-dashboard {
        padding: 9px 16px 10px;
        margin-bottom: 4px;
        border-bottom: 1px solid var(--border-soft);
        color: #666;
        font-size: 12px;
        font-weight: 500;
        letter-spacing: 0.3px;
    }
    .nav-item.is-dashboard.active { color: var(--accent); }

    .nav-dot {
        width: 6px; height: 6px;
        border-radius: 50%;
        flex-shrink: 0;
    }
    .nav-dot.critical { background: #ef4444; box-shadow: 0 0 5px rgba(239,68,68,0.5); }
    .nav-dot.warning  { background: #f97316; }
    .nav-dot.ok       { background: #22c55e; }
    .nav-dot.info     { background: #3b82f6; }

    .nav-num {
        font-family: var(--font-mono);
        font-size: 10px;
        color: #2e2e2e;
        width: 16px;
        flex-shrink: 0;
    }
    .nav-label {
        font-size: 12px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        flex: 1;
    }

    .sidebar-footer {
        padding: 9px 16px;
        border-top: 1px solid var(--border-soft);
        font-family: var(--font-mono);
        font-size: 9px;
        color: #222;
        letter-spacing: 0.5px;
    }

    /* ── Content area ── */
    .content {
        flex: 1;
        overflow-y: auto;
        scrollbar-width: thin;
        scrollbar-color: #222 transparent;
    }
    .content::-webkit-scrollbar { width: 5px; }
    .content::-webkit-scrollbar-thumb { background: #1e1e1e; border-radius: 3px; }

    /* ── Views (show/hide) ── */
    .view { display: none; }
    .view.active { display: block; }

    /* ── Content header (sticky) ── */
    .content-header {
        padding: 22px 36px 16px;
        border-bottom: 1px solid var(--border);
        position: sticky;
        top: 0;
        background: var(--bg-primary);
        z-index: 10;
    }
    .content-header::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 1px;
        background: linear-gradient(90deg, var(--accent), transparent 50%);
        opacity: 0.35;
    }
    .content-label {
        font-family: var(--font-mono);
        font-size: 9px;
        color: var(--accent);
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 4px;
    }
    .content-header h1 { font-size: 17px; font-weight: 600; color: #fff; }
    .header-meta-bar {
        display: flex;
        gap: 18px;
        flex-wrap: wrap;
        margin-top: 8px;
    }
    .header-meta-bar span {
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-muted);
    }
    .header-meta-bar span b { color: var(--text-primary); }

    /* ── Content body ── */
    .content-body { padding: 24px 36px 48px; }

    /* ── Dashboard summary cards ── */
    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-bottom: 32px;
    }
    .dashboard-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 22px 20px;
        text-align: center;
        position: relative;
        overflow: hidden;
    }
    .dashboard-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 2px;
    }
    .dashboard-card.critical::before { background: #ef4444; }
    .dashboard-card.warning::before  { background: #f97316; }
    .dashboard-card.ok::before       { background: #22c55e; }
    .dashboard-card.neutral::before  { background: #333; }
    .dash-count {
        font-size: 42px;
        font-weight: 700;
        font-family: var(--font-mono);
        line-height: 1;
        margin-bottom: 6px;
    }
    .dashboard-card.critical .dash-count { color: #ef4444; }
    .dashboard-card.warning  .dash-count { color: #f97316; }
    .dashboard-card.ok       .dash-count { color: #22c55e; }
    .dashboard-card.neutral  .dash-count { color: #444; }
    .dash-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }

    /* ── Section label ── */
    .section-label {
        font-family: var(--font-mono);
        font-size: 10px;
        color: var(--text-muted);
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 14px;
    }

    /* ── Module overview (dashboard table) ── */
    .module-row { cursor: pointer; transition: background 0.1s; }
    .module-row:hover td { background: rgba(0,212,255,0.04) !important; }

    /* ── Check Cards ── */
    .check-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        margin-bottom: 16px;
        overflow: hidden;
    }
    .check-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 20px;
        border-bottom: 1px solid var(--border);
        gap: 12px;
    }
    .check-title-group { display: flex; align-items: center; gap: 10px; flex: 1; min-width: 0; }
    .severity-badge {
        font-family: var(--font-mono);
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1px;
        padding: 3px 8px;
        border-radius: 3px;
        white-space: nowrap;
        flex-shrink: 0;
    }
    .severity-badge.critical { color: #ef4444; background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.3); }
    .severity-badge.warning  { color: #f97316; background: rgba(249,115,22,0.12); border: 1px solid rgba(249,115,22,0.3); }
    .severity-badge.ok       { color: #22c55e; background: rgba(34,197,94,0.12);  border: 1px solid rgba(34,197,94,0.3); }
    .severity-badge.info     { color: #3b82f6; background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.3); }
    .check-title { font-size: 14px; font-weight: 600; }
    .check-count {
        font-family: var(--font-mono);
        font-size: 13px;
        font-weight: 700;
        min-width: 60px;
        text-align: right;
        flex-shrink: 0;
    }
    .check-count.critical { color: #ef4444; }
    .check-count.warning  { color: #f97316; }
    .check-count.ok       { color: #22c55e; }
    .check-description {
        padding: 10px 20px 12px;
        color: var(--text-muted);
        font-size: 13px;
        border-bottom: 1px solid var(--border);
        line-height: 1.5;
    }

    /* ── Tables ── */
    .table-wrapper { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    thead th {
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1px;
        padding: 10px 20px;
        text-align: left;
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border);
        white-space: nowrap;
    }
    tbody tr { border-bottom: 1px solid rgba(42,42,42,0.5); }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:nth-child(even) { background: var(--bg-table-alt); }
    tbody td { padding: 10px 20px; font-size: 13px; }
    .mono { font-family: var(--font-mono); font-size: 12px; }
    .tag-list { display: flex; flex-wrap: wrap; gap: 4px; }
    .tag {
        font-family: var(--font-mono);
        font-size: 11px;
        background: rgba(0,212,255,0.06);
        border: 1px solid rgba(0,212,255,0.15);
        color: #aaa;
        padding: 1px 6px;
        border-radius: 3px;
    }
    .status-active   { color: #22c55e; }
    .status-disabled { color: #ef4444; }
    .risk-critical { color: #ef4444; font-weight: 600; }
    .risk-warning  { color: #f97316; }
    .risk-info     { color: #3b82f6; }
    .empty-state {
        padding: 20px;
        text-align: center;
        color: var(--text-muted);
        font-size: 13px;
    }

    /* ── Export button ── */
    .export-btn {
        font-family: var(--font-mono);
        font-size: 11px;
        color: #555;
        background: transparent;
        border: 1px solid #252525;
        padding: 6px 13px;
        border-radius: 4px;
        cursor: pointer;
        letter-spacing: 0.5px;
        white-space: nowrap;
        flex-shrink: 0;
        align-self: center;
        transition: color 0.15s, border-color 0.15s, background 0.15s;
    }
    .export-btn:hover {
        border-color: var(--accent);
        color: var(--accent);
        background: rgba(0,212,255,0.05);
    }
    """


def _get_js() -> str:
    return """
    function navigate(el) {
        var view = el.dataset.view;
        document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
        document.querySelectorAll('.view').forEach(function(v) { v.classList.remove('active'); });
        el.classList.add('active');
        var target = document.getElementById('view-' + view);
        if (target) target.classList.add('active');
        document.getElementById('main-content').scrollTop = 0;
    }
    function navigateToModule(viewId) {
        var navItem = document.querySelector('[data-view="' + viewId + '"]');
        if (navItem) navigate(navItem);
    }
    function exportModuleCSV(viewId, filename) {
        var view = document.getElementById('view-' + viewId);
        if (!view) return;
        var tables = view.querySelectorAll('table');
        if (!tables.length) return;
        var allRows = [];
        tables.forEach(function(table, idx) {
            if (idx > 0) allRows.push([]);
            table.querySelectorAll('tr').forEach(function(row) {
                var cols = row.querySelectorAll('th, td');
                var rowData = Array.from(cols).map(function(col) {
                    var text = (col.innerText || col.textContent || '').trim()
                        .replace(/\n+/g, ' ').replace(/"/g, '""');
                    return '"' + text + '"';
                });
                if (rowData.length) allRows.push(rowData);
            });
        });
        var csv = '﻿' + allRows.map(function(r) { return r.join(','); }).join('\n');
        var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.setAttribute('download', filename);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    }
    """


def _severity_badge(severity: str) -> str:
    cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["ok"])
    return f'<span class="severity-badge {severity}">{cfg["icon"]} {cfg["label"]}</span>'


def _render_generic_table(columns: list, rows: list, row_keys: list) -> str:
    """Renderiza uma tabela genérica dado colunas, rows e chaves de mapeamento."""
    if not rows:
        return '<div class="empty-state">✓ Nenhum achado nesta categoria</div>'

    thead = "".join(f"<th>{col}</th>" for col in columns)
    tbody_rows = []
    for row in rows:
        cells = "".join(f"<td class='mono'>{row.get(key, 'N/A')}</td>" for key in row_keys)
        tbody_rows.append(f"<tr>{cells}</tr>")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>{thead}</tr></thead>
        <tbody>{''.join(tbody_rows)}</tbody>
    </table>
    </div>
    """


def _render_password_check_table(check: dict) -> str:
    """Tabela para checks de políticas de password."""
    users = check.get("users", [])
    if not users:
        return '<div class="empty-state">✓ Nenhum achado nesta categoria</div>'

    columns = check.get("columns", [])
    thead = "".join(f"<th>{col}</th>" for col in columns)

    rows_html = []
    for u in users:
        username = u.get("username", "N/A")
        display  = u.get("display_name", "N/A")

        # Detectar colunas disponíveis dinamicamente
        if "uac" in u:
            cells = f"<td class='mono'>{username}</td><td>{display}</td><td class='mono'>{u.get('uac', 'N/A')}</td>"
        elif "pwd_age_days" in u:
            age     = u.get("pwd_age_days", "N/A")
            age_cls = "risk-critical" if isinstance(age, int) and age > 365 else ("risk-warning" if isinstance(age, int) and age > 90 else "")
            cells = (
                f"<td class='mono'>{username}</td>"
                f"<td>{display}</td>"
                f"<td>{u.get('pwd_last_set', 'N/A')}</td>"
                f"<td class='mono {age_cls}'>{age}</td>"
            )
        elif "last_logon" in u:
            cells = (
                f"<td class='mono'>{username}</td>"
                f"<td>{display}</td>"
                f"<td>{u.get('last_logon', 'N/A')}</td>"
            )
        else:
            cells = f"<td class='mono'>{username}</td><td>{display}</td>"

        rows_html.append(f"<tr>{cells}</tr>")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>{thead}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
    </table>
    </div>
    """


def _render_inactive_table(check: dict) -> str:
    """Tabela para contas inativas (utilizadores e computadores)."""
    items = check.get("users", check.get("computers", []))
    if not items:
        return '<div class="empty-state">✓ Nenhum achado nesta categoria</div>'

    columns = check.get("columns", [])
    thead = "".join(f"<th>{col}</th>" for col in columns)
    rows_html = []

    for item in items:
        days = item.get("inactive_days", "N/A")
        days_cls = "risk-critical" if isinstance(days, int) and days > 180 else ("risk-warning" if isinstance(days, int) else "")

        if "hostname" in item:
            # Computador
            cells = (
                f"<td class='mono'>{item.get('hostname','N/A')}</td>"
                f"<td class='mono'>{item.get('dns_name','N/A')}</td>"
                f"<td>{item.get('os','N/A')}</td>"
                f"<td>{item.get('last_logon','N/A')}</td>"
                f"<td class='mono {days_cls}'>{days}</td>"
            )
        elif "username" in item and "inactive_days" in item:
            cells = (
                f"<td class='mono'>{item.get('username','N/A')}</td>"
                f"<td>{item.get('display_name','N/A')}</td>"
                f"<td>{item.get('last_logon','N/A')}</td>"
                f"<td class='mono {days_cls}'>{days}</td>"
            )
        else:
            cells = (
                f"<td class='mono'>{item.get('username','N/A')}</td>"
                f"<td>{item.get('display_name','N/A')}</td>"
                f"<td>{item.get('last_logon','N/A')}</td>"
            )

        rows_html.append(f"<tr>{cells}</tr>")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>{thead}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
    </table>
    </div>
    """


def _render_group_table(check: dict) -> str:
    """Tabela para membros de grupos privilegiados."""
    members = check.get("members", [])
    if not members:
        return '<div class="empty-state">✓ Grupo vazio — configuração ideal para Schema/Enterprise Admins</div>'

    thead = "<th>Username</th><th>Nome Completo</th><th>Estado</th><th>Último Login</th><th>Email</th>"
    rows_html = []
    for m in members:
        status_cls = "status-disabled" if m.get("is_disabled") else "status-active"
        rows_html.append(f"""
        <tr>
            <td class='mono'>{m.get('username','N/A')}</td>
            <td>{m.get('display_name','N/A')}</td>
            <td class='{status_cls}'>{m.get('status','N/A')}</td>
            <td>{m.get('last_logon','N/A')}</td>
            <td class='mono'>{m.get('mail','N/A')}</td>
        </tr>""")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>{thead}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
    </table>
    </div>
    """


def _render_kerberoast_table(check: dict) -> str:
    """Tabela para alvos de Kerberoasting com SPNs expandidos."""
    users = check.get("users", [])
    if not users:
        return '<div class="empty-state">✓ Nenhum utilizador com SPNs encontrado</div>'

    thead = "<th>Username</th><th>SPNs Registados</th><th>Idade da Password</th><th>Último Login</th><th>Risco</th>"
    rows_html = []
    for u in users:
        spns = u.get("spns", [])
        spn_tags = " ".join(f"<span class='tag'>{s}</span>" for s in spns)

        age = u.get("pwd_age_days", "N/A")
        risk = u.get("risk", "info")
        risk_cls = f"risk-{risk}"
        risk_label = {"critical": "⚠ CRÍTICO", "warning": "ALTO", "info": "MÉDIO"}.get(risk, risk)

        rows_html.append(f"""
        <tr>
            <td class='mono'>{u.get('username','N/A')}</td>
            <td><div class='tag-list'>{spn_tags}</div></td>
            <td class='mono'>{age} dias</td>
            <td>{u.get('last_logon','N/A')}</td>
            <td class='{risk_cls}'>{risk_label}</td>
        </tr>""")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>{thead}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
    </table>
    </div>
    """


def _render_delegation_table(check: dict) -> str:
    """Tabela para delegação Kerberos — distingue unconstrained de constrained."""
    accounts = check.get("accounts", [])
    if not accounts:
        return '<div class="empty-state">✓ Nenhuma conta com este tipo de delegação encontrada</div>'

    is_constrained = "allowed_targets" in accounts[0]

    if is_constrained:
        thead = "<th>Username</th><th>Tipo</th><th>Serviços Permitidos</th><th>Protocol Transition</th><th>Risco</th>"
        rows_html = []
        for a in accounts:
            targets = a.get("allowed_targets", [])
            tags = " ".join(f"<span class='tag'>{t}</span>" for t in targets)
            risk = a.get("risk", "warning")
            risk_cls = f"risk-{risk}"
            risk_label = "⚠ CRÍTICO" if risk == "critical" else "MÉDIO"
            proto = a.get("protocol_transition", False)
            proto_html = (
                '<span class="risk-critical">Sim ⚠</span>' if proto
                else '<span style="color:#888">Não</span>'
            )
            rows_html.append(f"""
            <tr>
                <td class='mono'>{a.get('username','N/A')}</td>
                <td>{a.get('account_type','N/A')}</td>
                <td><div class='tag-list'>{tags if tags else '<span style="color:#888">—</span>'}</div></td>
                <td>{proto_html}</td>
                <td class='{risk_cls}'>{risk_label}</td>
            </tr>""")
    else:
        thead = "<th>Username</th><th>Nome / DNS</th><th>Tipo</th><th>Último Login</th><th>Risco</th>"
        rows_html = []
        for a in accounts:
            rows_html.append(f"""
            <tr>
                <td class='mono'>{a.get('username','N/A')}</td>
                <td>{a.get('display_name','N/A')}</td>
                <td>{a.get('account_type','N/A')}</td>
                <td>{a.get('last_logon','N/A')}</td>
                <td class='risk-critical'>⚠ CRÍTICO</td>
            </tr>""")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>{thead}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
    </table>
    </div>
    """


def _render_krbtgt_info(check: dict) -> str:
    """Card de informação para a conta krbtgt."""
    info = check.get("krbtgt")
    if not info:
        return '<div class="empty-state">⚠ Conta krbtgt não encontrada</div>'

    age = info.get("pwd_age_days", "N/A")
    severity = check.get("severity", "ok")
    age_cls = {
        "critical": "risk-critical",
        "warning":  "risk-warning",
        "ok":       "status-active",
    }.get(severity, "")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>
            <th>Conta</th>
            <th>Última Alteração de Password</th>
            <th>Idade da Password</th>
            <th>Último Login</th>
            <th>Estado</th>
        </tr></thead>
        <tbody>
        <tr>
            <td class='mono'>krbtgt</td>
            <td>{info.get('pwd_last_set','N/A')}</td>
            <td class='mono {age_cls}'>{age} dias</td>
            <td>{info.get('last_logon','N/A')}</td>
            <td class='{age_cls}'>{info.get('risk_label','N/A')}</td>
        </tr>
        </tbody>
    </table>
    </div>
    """


def _render_domain_policy_table(check: dict) -> str:
    """Renderiza a política de password ou a lista de PSOs."""
    # PSO list
    psos = check.get("psos")
    if psos is not None:
        if not psos:
            return '<div class="empty-state">Nenhuma Fine-Grained Password Policy configurada</div>'
        thead = "<th>Nome (PSO)</th><th>Precedência</th><th>Comprimento Mín.</th><th>Validade Máx.</th><th>Complexidade</th><th>Bloqueio</th><th>Targets</th>"
        rows = []
        for p in psos:
            age_val = p.get("max_age_days", "N/A")
            age_str = f"{age_val} dias" if isinstance(age_val, int) and age_val > 0 else ("Nunca expira" if age_val == 0 else "N/A")
            rows.append(f"""
            <tr>
                <td class='mono'>{p.get('name','N/A')}</td>
                <td class='mono'>{p.get('precedence','N/A')}</td>
                <td class='mono'>{p.get('min_length','N/A')} car.</td>
                <td>{age_str}</td>
                <td>{p.get('complexity','N/A')}</td>
                <td class='mono'>{p.get('lockout','N/A')}</td>
                <td class='mono'>{p.get('targets',0)} alvo(s)</td>
            </tr>""")
        return f"""
        <div class="table-wrapper">
        <table>
            <thead><tr>{thead}</tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
        </div>
        """

    # Default policy settings
    settings = check.get("settings", [])
    if not settings:
        return '<div class="empty-state">Configurações de política não disponíveis</div>'

    STATUS_STYLE = {
        "critical": ("risk-critical", "🔴"),
        "warning":  ("risk-warning",  "🟡"),
        "ok":       ("status-active", "🟢"),
    }
    rows = []
    for s in settings:
        cls, icon = STATUS_STYLE.get(s.get("status", "ok"), ("", ""))
        rec = s.get("recommendation", "")
        rec_html = f'<span style="color:#888;font-size:12px">{rec}</span>' if rec else "—"
        rows.append(f"""
        <tr>
            <td>{s.get('name','N/A')}</td>
            <td class='mono {cls}'>{icon} {s.get('value','N/A')}</td>
            <td>{rec_html}</td>
        </tr>""")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr><th>Configuração</th><th>Valor Atual</th><th>Recomendação</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
    </table>
    </div>
    """


def _render_os_inventory_table(check: dict) -> str:
    """Tabela de inventário SO — sumário por OS e lista de máquinas."""
    computers = check.get("computers", [])
    os_summary = check.get("os_summary", [])

    if not computers:
        return '<div class="empty-state">✓ Nenhum computador encontrado no domínio</div>'

    STATUS_STYLE = {
        "eol":     ("risk-critical", "🔴 EOL"),
        "legacy":  ("risk-warning",  "🟡 Legacy"),
        "current": ("status-active", "🟢 Atual"),
        "unknown": ("",              "⚪ Desconhecido"),
    }

    # Sumário por OS
    summary_rows = []
    for os_entry in os_summary:
        cls, label = STATUS_STYLE.get(os_entry.get("status", "unknown"), ("", ""))
        summary_rows.append(f"""
        <tr>
            <td>{os_entry.get('os', 'N/A')}</td>
            <td class='mono'>{os_entry.get('count', 0)}</td>
            <td class='{cls}'>{label}</td>
        </tr>""")

    summary_table = f"""
    <div style="padding:12px 20px 4px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase">
        Sumário por Sistema Operativo
    </div>
    <div class="table-wrapper">
    <table>
        <thead><tr><th>Sistema Operativo</th><th>Máquinas</th><th>Classificação</th></tr></thead>
        <tbody>{''.join(summary_rows)}</tbody>
    </table>
    </div>
    <div style="padding:12px 20px 4px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase">
        Detalhe por Máquina
    </div>"""

    # Detalhe por máquina
    detail_rows = []
    for c in computers:
        cls, label = STATUS_STYLE.get(c.get("status", "unknown"), ("", ""))
        disabled_html = '<span class="status-disabled">Desativado</span>' if c.get("disabled") else '<span class="status-active">Ativo</span>'
        detail_rows.append(f"""
        <tr>
            <td class='mono'>{c.get('name', 'N/A')}</td>
            <td>{c.get('os', 'N/A')}</td>
            <td class='mono'>{c.get('os_version', 'N/A')}</td>
            <td>{c.get('last_logon', 'N/A')}</td>
            <td>{disabled_html}</td>
            <td class='{cls}'>{label}</td>
        </tr>""")

    detail_table = f"""
    <div class="table-wrapper">
    <table>
        <thead><tr><th>Hostname</th><th>Sistema Operativo</th><th>Versão</th><th>Último Login</th><th>Estado</th><th>Classificação</th></tr></thead>
        <tbody>{''.join(detail_rows)}</tbody>
    </table>
    </div>"""

    return summary_table + detail_table


def _render_domain_trusts_table(check: dict) -> str:
    """Tabela de domain trusts com avaliação de risco."""
    trusts = check.get("trusts", [])

    if not trusts:
        return '<div class="empty-state">✓ Nenhuma relação de confiança configurada neste domínio</div>'

    rows = []
    for t in trusts:
        sid_html = (
            '<span class="status-active">Sim</span>'
            if t.get("sid_filtering")
            else '<span class="risk-critical">Não ⚠</span>'
        )
        flags = t.get("flags", [])
        flags_html = (
            " ".join(f"<span class='tag'>{f}</span>" for f in flags)
            if flags else '<span style="color:#888">—</span>'
        )
        risk_html = (
            '<span class="risk-critical">⚠ SID Attack</span>'
            if t.get("risky")
            else '<span style="color:#888">—</span>'
        )
        rows.append(f"""
        <tr>
            <td class='mono'>{t.get('name', 'N/A')}</td>
            <td class='mono'>{t.get('flat_name', 'N/A')}</td>
            <td>{t.get('trust_type', 'N/A')}</td>
            <td>{t.get('direction', 'N/A')}</td>
            <td>{sid_html}</td>
            <td><div class='tag-list'>{flags_html}</div></td>
            <td>{risk_html}</td>
        </tr>""")

    return f"""
    <div class="table-wrapper">
    <table>
        <thead><tr>
            <th>Domínio</th>
            <th>NetBIOS</th>
            <th>Tipo</th>
            <th>Direção</th>
            <th>SID Filtering</th>
            <th>Atributos</th>
            <th>Risco</th>
        </tr></thead>
        <tbody>{''.join(rows)}</tbody>
    </table>
    </div>
    """


def _render_adminsdholder_table(check: dict) -> str:
    """Tabela de contas orphaned com adminCount=1."""
    accounts = check.get("accounts", [])
    total    = check.get("total_admin_count", 0)
    active   = check.get("active_privileged", 0)
    orphaned = len(accounts)

    stats_html = f"""
    <div style="display:flex;gap:24px;padding:12px 20px;border-bottom:1px solid var(--border);font-size:13px;">
        <span>Total adminCount=1: <b class='mono'>{total}</b></span>
        <span>Em grupos privilegiados: <b class='mono' style='color:#22c55e'>{active}</b></span>
        <span>Orphaned: <b class='mono {"risk-critical" if orphaned > 0 else "status-active"}'>{orphaned}</b></span>
    </div>"""

    if not accounts:
        return stats_html + '<div class="empty-state">✓ Nenhuma conta orphaned — todas as contas com adminCount=1 pertencem a grupos privilegiados</div>'

    rows = []
    for a in accounts:
        disabled_html = '<span class="status-disabled">Desativado</span>' if a.get("disabled") else '<span class="status-active">Ativo</span>'
        rows.append(f"""
        <tr>
            <td class='mono'>{a.get('username', 'N/A')}</td>
            <td>{a.get('name', 'N/A')}</td>
            <td style='font-size:11px;color:#888'>{a.get('dn', 'N/A')}</td>
            <td>{disabled_html}</td>
        </tr>""")

    return stats_html + f"""
    <div class="table-wrapper">
    <table>
        <thead><tr><th>Username</th><th>Nome</th><th>Distinguished Name</th><th>Estado</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
    </table>
    </div>
    """


def _render_check_card(check: dict, module_type: str) -> str:
    """Renderiza um check card completo com header, descrição e tabela."""
    severity  = check.get("severity", "ok")
    title     = check.get("title", "Check")
    count     = check.get("count", 0)
    desc      = check.get("description", "")

    # Selecionar renderer de tabela correto
    if module_type == "password":
        table_html = _render_password_check_table(check)
    elif module_type == "inactive":
        table_html = _render_inactive_table(check)
    elif module_type == "groups":
        title = f"{check.get('group_name', title)}"
        table_html = _render_group_table(check)
    elif module_type == "kerberoast":
        table_html = _render_kerberoast_table(check)
    elif module_type == "delegation":
        table_html = _render_delegation_table(check)
    elif module_type == "krbtgt":
        table_html = _render_krbtgt_info(check)
    elif module_type == "domain_policy":
        table_html = _render_domain_policy_table(check)
    elif module_type == "os_inventory":
        table_html = _render_os_inventory_table(check)
    elif module_type == "domain_trusts":
        table_html = _render_domain_trusts_table(check)
    elif module_type == "adminsdholder":
        table_html = _render_adminsdholder_table(check)
    else:
        table_html = '<div class="empty-state">Sem dados</div>'

    # count_label pode ser sobreescrito pelo módulo (ex: "3 configurações fracas")
    count_label = check.get("count_label") or f"{count} encontrado{'s' if count != 1 else ''}"

    return f"""
    <div class="check-card">
        <div class="check-header">
            <div class="check-title-group">
                {_severity_badge(severity)}
                <span class="check-title">{title}</span>
            </div>
            <span class="check-count {severity}">{count_label}</span>
        </div>
        <div class="check-description">{desc}</div>
        {table_html}
    </div>
    """


def _count_severities(all_modules: list) -> dict:
    """Conta findings por severidade para o dashboard de sumário."""
    counts = {"critical": 0, "warning": 0, "ok": 0}
    for module in all_modules:
        for check in module.get("checks", []):
            sev = check.get("severity", "ok")
            if sev in counts:
                counts[sev] += 1
    return counts


def generate(all_modules: list) -> str:
    """Gera o HTML completo do relatório com layout sidebar + painel de conteúdo."""
    now       = datetime.now(tz=timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    date_str  = now.strftime("%Y-%m-%d")
    counts    = _count_severities(all_modules)
    total     = sum(counts.values())

    MODULE_TYPES = [
        "password", "inactive", "groups", "kerberoast", "delegation",
        "krbtgt", "domain_policy", "os_inventory", "domain_trusts", "adminsdholder",
    ]

    SEV_ORDER = {"critical": 0, "warning": 1, "ok": 2, "info": 3}

    def _module_severity(module: dict) -> str:
        checks = module.get("checks", [])
        if not checks:
            return "ok"
        return min(checks, key=lambda c: SEV_ORDER.get(c.get("severity", "ok"), 3)).get("severity", "ok")

    # ── Sidebar nav items ─────────────────────────────────────────────────────
    nav_items = """<a class="nav-item is-dashboard active" data-view="dashboard" onclick="navigate(this)">
        <span class="nav-label" style="color:inherit">⊞ &nbsp;Dashboard</span>
    </a>
    <div class="nav-section-label">// Módulos</div>"""

    for i, module in enumerate(all_modules):
        sev  = _module_severity(module)
        name = module.get("module_name", f"Módulo {i+1}")
        nav_items += f"""
    <a class="nav-item" data-view="module-{i}" onclick="navigate(this)">
        <span class="nav-dot {sev}"></span>
        <span class="nav-num">{i+1:02d}</span>
        <span class="nav-label">{name}</span>
    </a>"""

    # ── Module views ──────────────────────────────────────────────────────────
    module_views = ""
    for i, module in enumerate(all_modules):
        mtype       = MODULE_TYPES[i] if i < len(MODULE_TYPES) else "generic"
        name        = module.get("module_name", f"Módulo {i+1}")
        safe_name   = name.replace(" ", "-").replace("/", "-").replace("\\", "-")
        checks_html = "".join(_render_check_card(c, mtype) for c in module.get("checks", []))
        module_views += f"""
    <div class="view" id="view-module-{i}">
        <div class="content-header">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px">
                <div>
                    <div class="content-label">MOD-{i+1:02d}</div>
                    <h1>{name}</h1>
                </div>
                <button class="export-btn" onclick="exportModuleCSV('module-{i}','{safe_name}-{date_str}.csv')">↓ Exportar CSV</button>
            </div>
        </div>
        <div class="content-body">{checks_html}</div>
    </div>"""

    # ── Dashboard overview table ───────────────────────────────────────────────
    overview_rows = ""
    for i, module in enumerate(all_modules):
        sev        = _module_severity(module)
        sev_cfg    = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG["ok"])
        name       = module.get("module_name", f"Módulo {i+1}")
        checks     = module.get("checks", [])
        n_crit     = sum(1 for c in checks if c.get("severity") == "critical")
        n_warn     = sum(1 for c in checks if c.get("severity") == "warning")
        n_ok       = sum(1 for c in checks if c.get("severity") == "ok")
        crit_html  = f'<span style="color:#ef4444;font-family:var(--font-mono)">{n_crit}</span>' if n_crit else '<span style="color:#333">—</span>'
        warn_html  = f'<span style="color:#f97316;font-family:var(--font-mono)">{n_warn}</span>' if n_warn else '<span style="color:#333">—</span>'
        ok_html    = f'<span style="color:#22c55e;font-family:var(--font-mono)">{n_ok}</span>'   if n_ok   else '<span style="color:#333">—</span>'
        overview_rows += f"""
        <tr class="module-row" onclick="navigateToModule('module-{i}')">
            <td class="mono" style="color:var(--accent)">MOD-{i+1:02d}</td>
            <td>{name}</td>
            <td>{_severity_badge(sev)}</td>
            <td>{crit_html}</td>
            <td>{warn_html}</td>
            <td>{ok_html}</td>
        </tr>"""

    dashboard_view = f"""
    <div class="view active" id="view-dashboard">
        <div class="content-header">
            <div class="content-label">// Security Audit Report</div>
            <h1>Active Directory Security Audit</h1>
            <div class="header-meta-bar">
                <span>Domínio: <b>{config.DOMAIN}</b></span>
                <span>DC: <b>{config.DC_HOST}</b></span>
                <span>Base DN: <b>{config.BASE_DN}</b></span>
                <span>Auditado como: <b>{config.USERNAME}</b></span>
                <span>Gerado em: <b>{timestamp}</b></span>
            </div>
        </div>
        <div class="content-body">
            <div class="dashboard-grid">
                <div class="dashboard-card critical">
                    <div class="dash-count">{counts['critical']}</div>
                    <div class="dash-label">Críticos</div>
                </div>
                <div class="dashboard-card warning">
                    <div class="dash-count">{counts['warning']}</div>
                    <div class="dash-label">Avisos</div>
                </div>
                <div class="dashboard-card ok">
                    <div class="dash-count">{counts['ok']}</div>
                    <div class="dash-label">OK</div>
                </div>
                <div class="dashboard-card neutral">
                    <div class="dash-count">{total}</div>
                    <div class="dash-label">Total de Checks</div>
                </div>
            </div>

            <div class="section-label">// Resumo por Módulo</div>
            <div class="table-wrapper">
            <table>
                <thead><tr>
                    <th>Módulo</th><th>Nome</th><th>Severidade</th>
                    <th>Críticos</th><th>Avisos</th><th>OK</th>
                </tr></thead>
                <tbody>{overview_rows}</tbody>
            </table>
            </div>
        </div>
    </div>"""

    # ── HTML Final ────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Audit — {config.DOMAIN} — {date_str}</title>
    <style>{_get_css()}</style>
</head>
<body>
<div class="layout">
    <aside class="sidebar">
        <div class="sidebar-brand">
            <div class="brand-label">// AD Security Audit</div>
            <div class="brand-domain">{config.DOMAIN}</div>
            <div class="brand-meta">{config.DC_HOST} &nbsp;·&nbsp; {date_str}</div>
        </div>
        <div class="sidebar-stats">
            <div class="stat critical">
                <span class="stat-num">{counts['critical']}</span>
                <span class="stat-label">Críticos</span>
            </div>
            <div class="stat warning">
                <span class="stat-num">{counts['warning']}</span>
                <span class="stat-label">Avisos</span>
            </div>
            <div class="stat ok">
                <span class="stat-num">{counts['ok']}</span>
                <span class="stat-label">OK</span>
            </div>
        </div>
        <nav class="sidebar-nav" id="sidebar-nav">
            {nav_items}
        </nav>
        <div class="sidebar-footer">Projeto Final &nbsp;·&nbsp; SIRC</div>
    </aside>

    <main class="content" id="main-content">
        {dashboard_view}
        {module_views}
    </main>
</div>
<script>{_get_js()}</script>
</body>
</html>"""


def save(all_modules: list, output_path: str = None) -> str:
    """
    Gera e guarda o relatório HTML em disco.

    Args:
        all_modules: resultados agregados de todos os módulos
        output_path: caminho do ficheiro de output

    Returns:
        Caminho do ficheiro gerado
    """
    path = output_path or config.REPORT_OUTPUT_PATH
    html = generate(all_modules)

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n[OK] Relatório gerado: {path}")
        return path
    except IOError as e:
        print(f"[ERRO] Não foi possível guardar o relatório em '{path}': {e}")
        raise
