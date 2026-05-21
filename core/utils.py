"""
core/utils.py — Funções auxiliares para parsing de dados do Active Directory.

O AD armazena dados em formatos específicos que precisam de conversão:
  - Timestamps: formato FILETIME (inteiro de 100-nanosegundos desde 1601-01-01)
  - Flags de conta: bitmask UAC (UserAccountControl) — cada bit é um atributo
  - Distinguished Names: strings longas que precisam de extração do CN
"""

from datetime import datetime, timezone, timedelta


# ─── Constantes UAC (UserAccountControl bitmask) ─────────────────────────────
# Referência: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
UAC_FLAGS = {
    "SCRIPT":                          0x0001,
    "ACCOUNTDISABLE":                  0x0002,
    "HOMEDIR_REQUIRED":                0x0008,
    "LOCKOUT":                         0x0010,
    "PASSWD_NOTREQD":                  0x0020,   # Password não obrigatória
    "PASSWD_CANT_CHANGE":              0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED":      0x0080,
    "NORMAL_ACCOUNT":                  0x0200,
    "DONT_EXPIRE_PASSWORD":            0x10000,  # Password nunca expira
    "PASSWORD_EXPIRED":                0x800000,
    "TRUSTED_FOR_DELEGATION":          0x80000,  # Kerberos delegation — risco alto
    "NOT_DELEGATED":                   0x100000,
    "USE_DES_KEY_ONLY":                0x200000, # Cifra fraca — risco alto
    "DONT_REQ_PREAUTH":                0x400000, # ASREPRoasting target!
}

# Epoch do Windows FILETIME: 1 de Janeiro de 1601
WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Offset entre Windows epoch e Unix epoch em microsegundos
EPOCH_DIFF_SECONDS = 11644473600


def filetime_to_datetime(filetime_value) -> datetime | None:
    """
    Converte um timestamp FILETIME do AD para um objeto datetime Python.

    O FILETIME é um inteiro de 64 bits representando o número de
    intervalos de 100 nanossegundos desde 1 de Janeiro de 1601 UTC.

    Valores especiais:
      - 0 ou None: atributo não definido (ex: nunca fez login)
      - 9223372036854775807 (0x7FFFFFFFFFFFFFFF): "nunca expira"

    Args:
        filetime_value: valor FILETIME como int ou string

    Returns:
        datetime (UTC) ou None se o valor for inválido/especial
    """
    if not filetime_value:
        return None
    try:
        ft = int(filetime_value)
        # Valores especiais do AD
        if ft == 0 or ft == 9223372036854775807:
            return None
        # Converter: dividir por 10^7 para obter segundos, subtrair offset
        unix_timestamp = (ft / 10_000_000) - EPOCH_DIFF_SECONDS
        return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def days_since(dt: datetime | None) -> int | None:
    """
    Calcula quantos dias passaram desde um datetime.

    Returns:
        Número de dias (inteiro) ou None se dt for None
    """
    if dt is None:
        return None
    now = datetime.now(tz=timezone.utc)
    delta = now - dt
    return delta.days


def has_uac_flag(uac_value, flag_name: str) -> bool:
    """
    Verifica se um flag UAC específico está ativo.

    Args:
        uac_value: valor UAC como int ou string
        flag_name: nome do flag (ex: "DONT_EXPIRE_PASSWORD")

    Returns:
        True se o flag estiver ativo, False caso contrário
    """
    if uac_value is None:
        return False
    try:
        uac_int = int(uac_value)
        flag_bit = UAC_FLAGS.get(flag_name, 0)
        return bool(uac_int & flag_bit)
    except (ValueError, TypeError):
        return False


def extract_cn(distinguished_name: str) -> str:
    """
    Extrai o Common Name (CN) de um Distinguished Name (DN) LDAP.

    Ex: "CN=John Doe,OU=Users,DC=corp,DC=local" → "John Doe"

    Args:
        distinguished_name: DN completo

    Returns:
        CN extraído, ou o DN original se a extração falhar
    """
    if not distinguished_name:
        return ""
    try:
        parts = distinguished_name.split(",")
        first = parts[0].strip()
        if first.upper().startswith("CN="):
            return first[3:]
    except (AttributeError, IndexError):
        pass
    return distinguished_name


def format_date(dt: datetime | None, fmt: str = "%Y-%m-%d") -> str:
    """Formata um datetime para string legível. Devolve 'N/A' se None."""
    if dt is None:
        return "N/A"
    return dt.strftime(fmt)


def get_display_name(entry) -> str:
    """
    Constrói o nome completo do utilizador a partir dos atributos disponíveis.
    Tenta por ordem: displayName → givenName+sn → cn → sAMAccountName.
    Necessário porque alguns scripts de lab (ex: Vulnerable-AD) não populam displayName.
    """
    display = get_attr(entry, "displayName", None)
    if display:
        return str(display)
    given = get_attr(entry, "givenName", None)
    sn    = get_attr(entry, "sn", None)
    if given or sn:
        return " ".join(p for p in [given, sn] if p)
    cn = get_attr(entry, "cn", None)
    if cn:
        return str(cn)
    return get_attr(entry, "sAMAccountName", "N/A") or "N/A"


def get_attr(entry, attr_name: str, default=None):
    """
    Extrai um atributo de uma entrada LDAP de forma segura.

    O ldap3 devolve atributos como listas; esta função trata da
    extração do primeiro valor e de atributos ausentes.

    Args:
        entry: entrada LDAP (ldap3 Entry object)
        attr_name: nome do atributo LDAP
        default: valor a devolver se o atributo não existir

    Returns:
        Valor do atributo ou default
    """
    try:
        attr = getattr(entry, attr_name, None)
        if attr is None:
            return default
        val = attr.value
        if isinstance(val, list):
            return val[0] if val else default
        return val if val is not None else default
    except Exception:
        return default
