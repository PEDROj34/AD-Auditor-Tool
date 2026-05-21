#!/usr/bin/env python3
"""
main.py — Orquestrador principal do AD Security Auditor.

Uso:
    python main.py
    python main.py --dc 192.168.1.10 --domain corp.local --user jdoe --password P@ss

O script autentica com credenciais de utilizador comum (sem privilégios de admin)
e executa todos os módulos de auditoria sequencialmente, gerando um relatório HTML.

Perspetiva simulada: utilizador de domínio que acabou de obter acesso inicial
(ex: phishing, password spraying) ou auditor de segurança interno.
"""

import argparse
import sys
import os
from datetime import datetime

# Forçar UTF-8 no stdout/stderr para compatibilidade com Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# ── Override de config via CLI ────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="AD Security Auditor — Ferramenta de auditoria LDAP para Active Directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python main.py
  python main.py --dc 10.0.0.1 --domain empresa.pt --user jdoe --password Pass123
  python main.py --output resultados/audit_2024.html --inactive-days 60
        """
    )
    parser.add_argument("--dc",            metavar="IP",   help="IP/hostname do Domain Controller")
    parser.add_argument("--domain",        metavar="FQDN", help="FQDN do domínio (ex: corp.local)")
    parser.add_argument("--user",          metavar="USER", help="Username (sAMAccountName)")
    parser.add_argument("--password",      metavar="PASS", help="Password do utilizador")
    parser.add_argument("--output",        metavar="PATH", help="Caminho do relatório HTML de output")
    parser.add_argument("--inactive-days", metavar="N",    type=int, help="Dias para considerar conta inativa (default: 90)")
    parser.add_argument("--no-report",     action="store_true",      help="Não gerar relatório HTML (só output no terminal)")
    return parser.parse_args()


def apply_cli_overrides(args):
    """Aplica overrides de CLI às configurações, sem modificar config.py."""
    import config
    if args.dc:            config.DC_HOST             = args.dc
    if args.domain:
        config.DOMAIN  = args.domain
        config.BASE_DN = ",".join(f"DC={p}" for p in args.domain.split("."))
    if args.user:          config.USERNAME            = args.user
    if args.password:      config.PASSWORD            = args.password
    if args.output:        config.REPORT_OUTPUT_PATH  = args.output
    if args.inactive_days: config.INACTIVE_DAYS       = args.inactive_days


def print_banner():
    banner = r"""
  ┌─────────────────────────────────────────────────────────┐
  │          AD SECURITY AUDITOR — Projeto Final            │
  │     Segurança Informática e Redes de Computadores       │
  │                                                         │
  │  Perspetiva: Utilizador de domínio sem admin rights     │
  │  Protocolo:  LDAPv3 via ldap3 (Python)                  │
  └─────────────────────────────────────────────────────────┘
    """
    print(banner)


def ensure_output_dir():
    """Garante que o diretório de output existe."""
    import config
    output_dir = os.path.dirname(config.REPORT_OUTPUT_PATH)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)


def main():
    args = parse_args()
    apply_cli_overrides(args)

    print_banner()

    import config
    print(f"[*] Alvo:    {config.DOMAIN} ({config.DC_HOST}:{config.DC_PORT})")
    print(f"[*] Base DN: {config.BASE_DN}")
    print(f"[*] User:    {config.USERNAME}")
    print(f"[*] Início:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ── 1. Estabelecer ligação LDAP ────────────────────────────────────────────
    from core.connector import get_connection, close_connection
    conn = get_connection()
    print()

    # ── 2. Executar módulos de auditoria ──────────────────────────────────────
    from modules import (
        password_policy, inactive_accounts, privileged_groups,
        kerberoasting, delegation, krbtgt_check, domain_policy,
        os_inventory, domain_trusts, adminsdholder,
    )

    all_results = []

    try:
        # Módulo 1: Políticas de Password e Contas
        all_results.append(password_policy.run(conn))
        print()

        # Módulo 2: Contas Órfãs e Inativas
        all_results.append(inactive_accounts.run(conn))
        print()

        # Módulo 3: Grupos Privilegiados
        all_results.append(privileged_groups.run(conn))
        print()

        # Módulo 4: Kerberoasting
        all_results.append(kerberoasting.run(conn))
        print()

        # Módulo 5: Delegação Kerberos
        all_results.append(delegation.run(conn))
        print()

        # Módulo 6: Conta krbtgt
        all_results.append(krbtgt_check.run(conn))
        print()

        # Módulo 7: Política de Password do Domínio
        all_results.append(domain_policy.run(conn))
        print()

        # Módulo 8: Inventário de Sistemas Operativos / EOL
        all_results.append(os_inventory.run(conn))
        print()

        # Módulo 9: Domain Trusts
        all_results.append(domain_trusts.run(conn))
        print()

        # Módulo 10: AdminSDHolder / Orphaned adminCount
        all_results.append(adminsdholder.run(conn))
        print()

    except KeyboardInterrupt:
        print("\n[!] Auditoria interrompida pelo utilizador.")
        close_connection(conn)
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERRO] Erro inesperado durante a auditoria: {e}")
        import traceback
        traceback.print_exc()
        close_connection(conn)
        sys.exit(1)

    # ── 3. Encerrar sessão LDAP ────────────────────────────────────────────────
    close_connection(conn)

    # ── 4. Gerar relatório HTML ────────────────────────────────────────────────
    if not args.no_report:
        ensure_output_dir()
        from reporter import html_report
        report_path = html_report.save(all_results)
        print(f"[*] Abrir no browser: file://{os.path.abspath(report_path)}")
    else:
        print("[*] Relatório HTML não gerado (--no-report ativo).")

    print(f"\n[*] Auditoria concluída: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
