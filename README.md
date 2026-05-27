# AD Security Auditor

Ferramenta de auditoria de segurança para Active Directory via LDAP. Identifica más configurações comuns utilizando apenas um utilizador de domínio comum — sem necessidade de privilégios de administrador.

> **Uso autorizado apenas.** Esta ferramenta deve ser executada exclusivamente em ambientes onde tenhas autorização explícita para realizar auditorias de segurança.

---

## O que audita

| Módulo | Área | Checks |
|--------|------|--------|
| **1 — Políticas de Password** | Contas | Contas com password não obrigatória (PASSWD_NOTREQD), passwords sem expiração (DONT_EXPIRE_PASSWORD), passwords antigas (> 90 dias), contas vulneráveis a ASREPRoasting (DONT_REQ_PREAUTH) |
| **2 — Contas Inativas** | Contas | Utilizadores sem login há mais de 90 dias, computadores inativos, contas desativadas ainda presentes no AD |
| **3 — Grupos Privilegiados** | Controlo de Acesso | Membros de Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Group Policy Creator Owners |
| **4 — Kerberoasting** | Kerberos | Utilizadores com `servicePrincipalName` definido, classificados por risco (password antiga, membro de grupo privilegiado) |
| **5 — Delegação Kerberos** | Kerberos | Unconstrained delegation (recebe TGTs completos), constrained delegation, protocol transition (impersonation sem pré-auth) |
| **6 — Conta krbtgt** | Kerberos | Idade da password da conta krbtgt — base dos Golden Tickets; crítico se > 365 dias ou `pwdLastSet=0` |
| **7 — Política de Password** | Configuração | Default Domain Password Policy (comprimento, complexidade, histórico, bloqueio), Fine-Grained Password Policies (PSOs) |
| **8 — Inventário SO / EOL** | Infraestrutura | Sistemas operativos de todos os computadores do domínio; classifica EOL (XP/Vista/7/Server 2003/2008), Legacy (8.1/Server 2012) e Atual |
| **9 — Domain Trusts** | Infraestrutura | Relações de confiança inter-domínio: tipo, direção, estado do SID filtering (QUARANTINE_DOMAIN) — trusts sem SID filtering são vulneráveis a SID History attacks |
| **10 — AdminSDHolder** | Persistência | Contas com `adminCount=1` que já não pertencem a nenhum grupo privilegiado — "orphaned", retêm ACLs restritivos do SDProp e podem ser usadas para persistência |

O resultado é um relatório HTML autónomo com dashboard de severidade, exportável sem dependências externas.

---

## Pré-requisitos

- Python 3.10 ou superior
- Acesso de rede ao Domain Controller na porta 389 (LDAP) ou 636 (LDAPS)
- Credenciais de um utilizador de domínio comum (Domain Users é suficiente)

> **Nota Python 3.13+:** O Python 3.13 removeu o MD4 da stdlib. O `pycryptodome` (incluído nos requirements) fornece essa dependência para o NTLM do ldap3.

---

## Instalação

```bash
# 1. Clonar ou copiar o projeto
git clone <repositório> ad_auditor
cd ad_auditor

# 2. Criar ambiente virtual (recomendado)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Instalar dependências
pip install -r requirements.txt
```

---

## Configuração

### `config.py` — obrigatório

O ficheiro `config.py` **tem de existir e estar configurado** antes de executar a ferramenta. Todos os módulos importam-no directamente para ler os parâmetros de ligação, limiares de auditoria e a lista de grupos privilegiados.

Edita os valores para o teu ambiente:

```python
# ─── Ligação ao Domain Controller ────────────────────────────────────────────
DC_HOST   = "10.0.0.1"        # IP ou hostname do Domain Controller
DC_PORT   = 389               # 389 = LDAP, 636 = LDAPS
USE_SSL   = False             # True para LDAPS (porta 636)
USE_TLS   = False             # STARTTLS sobre porta 389

# ─── Credenciais ──────────────────────────────────────────────────────────────
DOMAIN    = "empresa.pt"      # FQDN do domínio
USERNAME  = "auditor"         # sAMAccountName (só o username, sem domínio)
PASSWORD  = "P@ssword123"     # Nunca commitar em produção

# ─── Limiares de auditoria ────────────────────────────────────────────────────
INACTIVE_DAYS       = 90      # Dias sem login para considerar conta inativa
OLD_PASSWORD_DAYS   = 90      # Dias sem alteração de password para aviso
REPORT_OUTPUT_PATH  = "output/report.html"

# ─── Fallback de grupos privilegiados (Módulo 3) ─────────────────────────────
# Usado apenas se a auto-descoberta via adminCount=1 falhar.
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Group Policy Creator Owners",
]
```

> **Segurança:** nunca commites o `config.py` com credenciais reais. Adiciona-o ao `.gitignore` em ambientes partilhados.

### Argumentos de linha de comandos — substituição pontual

Os argumentos CLI sobrepõem-se aos valores do `config.py` no momento da execução, mas **não substituem o ficheiro** — o `config.py` continua a ser necessário. Útil para mudar o alvo sem editar o ficheiro:

```bash
python main.py \
  --dc 10.0.0.1 \
  --domain empresa.pt \
  --user auditor \
  --password "P@ssword123" \
  --output relatorios/auditoria_2024-06.html
```

Os parâmetros `PRIVILEGED_GROUPS`, `INACTIVE_DAYS` e `OLD_PASSWORD_DAYS` **só são configuráveis via `config.py`** — não têm equivalente em linha de comandos (excepto `--inactive-days`).

---

## Utilização

### Execução básica

```bash
python main.py --dc 10.0.0.1 --domain empresa.pt --user auditor --password "Pass123"
```

### Todas as opções

```
opções:
  --dc IP           IP ou hostname do Domain Controller
  --domain FQDN     FQDN do domínio (ex: empresa.pt)
  --user USER       Username (sAMAccountName)
  --password PASS   Password do utilizador
  --output PATH     Caminho do relatório HTML (default: output/report.html)
  --inactive-days N Dias para considerar conta inativa (default: 90)
  --no-report       Não gerar relatório HTML (só output no terminal)
```

### Exemplos

```bash
# Auditoria completa com output personalizado
python main.py --dc dc01.empresa.pt --domain empresa.pt \
               --user joao.silva --password "Pass123!" \
               --output auditorias/empresa_maio_2025.html

# Ajustar limiar de inatividade para 60 dias
python main.py --dc 10.0.0.1 --domain empresa.pt \
               --user auditor --password "Pass123!" \
               --inactive-days 60

# Só output no terminal, sem gerar HTML
python main.py --dc 10.0.0.1 --domain empresa.pt \
               --user auditor --password "Pass123!" \
               --no-report
```

---

## Relatório HTML

O relatório gerado em `output/report.html` é um ficheiro standalone (sem dependências externas) que pode ser aberto em qualquer browser ou partilhado por email.

Inclui:
- **Dashboard** com contagem de findings críticos, avisos e checks OK
- **Tabelas detalhadas** por módulo com username, nome completo, datas e classificação de risco
- **Badges de severidade** (🔴 Crítico / 🟡 Aviso / 🟢 OK) por check

---

## Conta de utilizador necessária

A ferramenta funciona com um utilizador **Domain Users** padrão. Não são necessários privilégios de administrador — a leitura de atributos de utilizadores, grupos e políticas via LDAP está disponível a qualquer utilizador autenticado no domínio por omissão.

Se as queries devolverem zero resultados, verifica se:
- A conta não tem restrições de leitura LDAP aplicadas por GPO
- O acesso à porta 389 não está bloqueado por firewall entre o cliente e o DC
- As credenciais estão corretas (o bind NTLM falha silenciosamente em algumas configurações)

---

## Considerações de segurança para uso empresarial

**Antes de executar:**
- Obtém autorização escrita do responsável de TI ou CISO
- Regista a data, hora e conta utilizada para fins de auditoria
- Informa o SOC se existir monitorização de eventos LDAP (Event ID 1644 no DC)

**Durante a execução:**
- A ferramenta é read-only — não modifica nenhum objeto no AD
- Gera tráfego LDAP visível nos logs do Domain Controller
- Em domínios muito grandes (> 50 000 objetos), a execução pode demorar vários minutos

**Após a execução:**
- O relatório HTML pode conter informação sensível (nomes de contas privilegiadas, configurações de segurança) — trata-o como documento confidencial
- Não guardes o relatório em partilhas de rede acessíveis a utilizadores não autorizados

---

## LDAPS / STARTTLS (recomendado em produção)

Por omissão a ferramenta usa LDAP simples (porta 389, sem cifra). Em ambiente empresarial recomenda-se usar LDAPS:

```python
# config.py para LDAPS
DC_PORT = 636
USE_SSL = True
USE_TLS = False
```

Ou STARTTLS (cifra o canal após ligação inicial na porta 389):

```python
DC_PORT = 389
USE_SSL = False
USE_TLS = True
```

---

## Estrutura do projeto

```
ad_auditor/
├── main.py                   # Orquestrador e argumentos CLI
├── config.py                 # Parâmetros de ligação (não commitar com credenciais)
├── requirements.txt
├── core/
│   ├── connector.py          # Ligação LDAP com autenticação NTLM
│   └── utils.py              # Helpers: parse FILETIME, UAC flags, display name
├── modules/
│   ├── password_policy.py    # Módulo 1: flags UAC e ASREPRoasting
│   ├── inactive_accounts.py  # Módulo 2: contas/computadores inativos
│   ├── privileged_groups.py  # Módulo 3: membros de grupos críticos
│   ├── kerberoasting.py      # Módulo 4: SPNs em contas de utilizador
│   ├── delegation.py         # Módulo 5: delegação Kerberos (unconstrained/constrained)
│   ├── krbtgt_check.py       # Módulo 6: idade da password da conta krbtgt
│   ├── domain_policy.py      # Módulo 7: Default Domain Policy e PSOs
│   ├── os_inventory.py       # Módulo 8: inventário SO e sistemas EOL
│   ├── domain_trusts.py      # Módulo 9: domain trusts e SID filtering
│   └── adminsdholder.py      # Módulo 10: contas adminCount orphaned
├── reporter/
│   └── html_report.py        # Geração do relatório HTML standalone
└── output/
    └── report.html           # Relatório gerado (criado automaticamente)
```

---

## Dependências

| Pacote | Versão mínima | Função |
|--------|---------------|--------|
| `ldap3` | 2.9.1 | Cliente LDAP, autenticação NTLM |
| `pycryptodome` | 3.19.0 | MD4 para NTLM (necessário no Python 3.13+) |
