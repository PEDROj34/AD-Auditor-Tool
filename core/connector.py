"""
core/connector.py — Gestão da sessão LDAP com o Active Directory.

Responsabilidade única: estabelecer, validar e encerrar a ligação LDAP.
Todos os módulos de auditoria recebem um objeto `Connection` já autenticado.

Interação com o AD:
  - Protocolo: LDAPv3 via ldap3
  - Auth:      NTLM (compatível com AD sem necessitar de Kerberos no cliente)
  - Bind:      NTLM bind com credenciais de utilizador comum
  - Queries:   Cada módulo faz search() com filtros LDAP e atributos específicos
               para minimizar dados transferidos (eficiência de rede)
"""

import sys
from ldap3 import (
    Server, Connection, NTLM, SUBTREE,
    Tls, SYNC, ALL_ATTRIBUTES
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPExceptionError,
)
import ssl
import config


def build_upn(username: str, domain: str) -> str:
    """
    Constrói o User Principal Name para autenticação NTLM.
    Ex: jdoe + corp.local → CORP\\jdoe (formato NetBIOS)
    O ldap3 com NTLM aceita tanto UPN como DOMAIN\\user.
    """
    netbios = domain.split(".")[0].upper()
    return f"{netbios}\\{username}"


def get_connection() -> Connection:
    """
    Estabelece e devolve uma sessão LDAP autenticada ao Domain Controller.

    Fluxo:
      1. Cria objeto Server com endereço e porto do DC
      2. Configura TLS se USE_TLS=True (STARTTLS — cifra o canal sem SSL nativo)
      3. Autentica via NTLM (funciona com credenciais de utilizador comum)
      4. Valida o bind — se falhar, termina com mensagem clara

    Returns:
        ldap3.Connection: sessão autenticada e pronta para queries

    Raises:
        SystemExit: em caso de falha de rede ou credenciais inválidas
    """
    # ── 1. Configuração TLS opcional ─────────────────────────────────────────
    tls_config = None
    if config.USE_TLS and not config.USE_SSL:
        tls_config = Tls(validate=ssl.CERT_NONE)  # Em produção: CERT_REQUIRED
        # Nota para o relatório: CERT_NONE é aceitável em lab; num pentest real,
        # validar o certificado do DC evita MITM sobre o canal LDAP.

    # ── 2. Definição do servidor ──────────────────────────────────────────────
    try:
        server = Server(
            host=config.DC_HOST,
            port=config.DC_PORT,
            use_ssl=config.USE_SSL,
            tls=tls_config,
            get_info="ALL",   # Recolhe schema e rootDSE (útil para debug)
            connect_timeout=5,
        )
    except Exception as e:
        print(f"[ERRO] Falha ao definir servidor LDAP: {e}", file=sys.stderr)
        sys.exit(1)

    # ── 3. Ligação e autenticação NTLM ────────────────────────────────────────
    upn = build_upn(config.USERNAME, config.DOMAIN)
    try:
        conn = Connection(
            server=server,
            user=upn,
            password=config.PASSWORD,
            authentication=NTLM,
            client_strategy=SYNC,        # Síncrono, popula conn.entries após search
            raise_exceptions=True,
            read_only=True,             # Segurança: previne escritas acidentais
        )
        conn.open()

        # STARTTLS — elevar a ligação para cifrada antes do bind
        if config.USE_TLS and not config.USE_SSL:
            conn.start_tls()

        conn.bind()

    except LDAPBindError as e:
        print(f"\n[ERRO] Falha de autenticação (credenciais inválidas ou conta bloqueada).", file=sys.stderr)
        print(f"       Detalhe: {e}", file=sys.stderr)
        sys.exit(1)
    except LDAPSocketOpenError as e:
        print(f"\n[ERRO] Não foi possível ligar ao DC {config.DC_HOST}:{config.DC_PORT}.", file=sys.stderr)
        print(f"       Verifique o endereço IP, porto, e conectividade de rede.", file=sys.stderr)
        print(f"       Detalhe: {e}", file=sys.stderr)
        sys.exit(1)
    except LDAPExceptionError as e:
        print(f"\n[ERRO] Erro LDAP inesperado durante a ligação: {e}", file=sys.stderr)
        sys.exit(1)

    # ── 4. Confirmação ────────────────────────────────────────────────────────
    if not conn.bound:
        print("[ERRO] Bind LDAP falhou sem exceção. Verifique as configurações.", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] Ligado ao DC {config.DC_HOST} como {upn}")
    return conn


def close_connection(conn: Connection) -> None:
    """Encerra a sessão LDAP de forma limpa."""
    try:
        if conn and conn.bound:
            conn.unbind()
            print("[OK] Sessão LDAP encerrada.")
    except LDAPExceptionError as e:
        print(f"[AVISO] Erro ao encerrar sessão LDAP: {e}", file=sys.stderr)
