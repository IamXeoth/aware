# 🧠 AWARE

**Cognitive Awareness for Developers**

> *"Ferramentas não evitam erros. Consciência evita."*

AWARE é uma ferramenta local e privacy-first que atua como guardião cognitivo no fluxo de desenvolvimento, interceptando decisões técnicas perigosas e forçando consciência antes da execução.

[![PyPI version](https://badge.fury.io/py/aware-security.svg)](https://badge.fury.io/py/aware-security)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

- 🛡️ **Shell Wrapper** - Intercepta comandos perigosos (`rm -rf /`, `git push --force`)
- 🪝 **Git Hooks** - Pre-commit e pre-push automáticos
- 🔍 **Code Scanner** - Detecta secrets, debug mode, CORS issues
- 🎨 **Multiple Outputs** - Console, JSON, SARIF, GitHub Annotations
- 🔒 **Privacy-First** - 100% offline, zero telemetria
- ⚡ **Fast** - Analisa apenas diffs, não o repo inteiro

---

## 🚀 Quick Start

### Instalação
```bash
pipx install aware-security
```

### Instalar Git Hooks
```bash
cd seu-projeto
aware install
```

Agora `git commit` e `git push` executam AWARE automaticamente! ✅

### Uso Manual
```bash
# Scanneia arquivos staged
aware scan --staged

# Intercepta comando perigoso
aware wrap rm -rf /tmp/old

# Scanneia diff antes do push
aware scan --diff origin/main...HEAD
```

---

## 📋 Comandos

### `aware scan`

Scanneia código em busca de decisões perigosas:
```bash
# Pre-commit
aware scan --staged

# Pre-push
aware scan --diff origin/main...HEAD

# Output JSON
aware scan --staged --format json

# Verbose mode
aware scan --staged --verbose
```

### `aware wrap`

Intercepta e analisa comando antes de executar:
```bash
# Comando perigoso (requer token "RM")
aware wrap rm -rf /

# Git force push (requer token "PUSH")
aware wrap git push --force

# Curl insecure (requer y/N)
aware wrap curl -k https://api.internal
```

### `aware install`

Instala git hooks:
```bash
# Todos os hooks
aware install

# Apenas pre-commit
aware install --hook pre-commit
```

### `aware rules`

Gerencia regras:
```bash
# Lista regras
aware rules list

# Por categoria
aware rules list --by-risk

# Explica regra
aware rules explain SEC_ENV_FILE_COMMITTED

# Valida arquivo customizado
aware rules validate custom_rules.yaml
```

---

## 🎯 Regras Incluídas (25)

### 🔑 Secrets Exposed
- `.env` commitado
- API keys hardcoded
- AWS credentials
- Senhas hardcoded
- Database URLs com senha
- Chaves privadas (SSH, TLS)

### 🔓 TLS Disabled
- `verify=False` (Python)
- `rejectUnauthorized: false` (Node)
- `curl -k` / `--insecure`

### 🐛 Debug in Production
- `DEBUG=True`
- `NODE_ENV=development`
- Logs sensíveis (passwords, tokens)

### 🌐 CORS Misconfiguration
- `origin: *`
- `credentials: true` + wildcard

### 🔐 Auth Weakness
- JWT sem expiração
- Secret keys fracas
- Senhas hardcoded

### 💣 Destructive Commands
- `rm -rf` em paths perigosos
- `git push --force`
- `git reset --hard`
- `docker system prune -a`
- `DROP DATABASE`

---

## 🎨 Outputs

### Console (Default)
```
🔍 AWARE Scan (STAGED) - 2 findings

━━━ CRITICAL (1) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚨 Arquivo .env detectado no commit
   📍 .env
   Evidence: .env

━━━ HIGH (1) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  Modo debug ativado
   📍 src/config.py:+
   Evidence: DEBUG = True

──────────────────────────────────────────────────────────────
Total de findings: 2
❌ Exit code: 20 (Blocked)
──────────────────────────────────────────────────────────────
```

### JSON
```bash
aware scan --staged --format json
```

### SARIF (GitHub Code Scanning)
```bash
aware scan --staged --format sarif --output aware.sarif
```

### GitHub Annotations
```bash
aware scan --staged --format github
```

---

## ⚙️ Configuração

### Arquivo `.aware.yaml` (opcional)
```yaml
rules:
  disable:
    - CODE_DEBUG_TRUE
  elevate:
    CODE_CORS_STAR: critical

ignore:
  - "node_modules/**"
  - "venv/**"

policy:
  default_action_for_critical: block
```

### Regras Customizadas
```yaml
# custom_rules.yaml
version: "1.0"
rules:
  - id: CUSTOM_RULE
    risk: SECRETS_EXPOSED
    severity: high
    action: warn
    type: code_regex
    match:
      patterns:
        - "my_secret\\s*=\\s*['\"].*['\"]"
      file_globs:
        - "**/*.py"
    message: "Secret detectado"
    impact: "Expõe informação sensível"
    recommendation: "Use variável de ambiente"
```
```bash
aware scan --staged --rules custom_rules.yaml
```

---

## 🔧 Integração CI/CD

### GitHub Actions
```yaml
name: AWARE Security Scan

on: [push, pull_request]

jobs:
  aware:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Install AWARE
        run: pipx install aware-security
      
      - name: Scan
        run: aware scan --diff origin/main...HEAD --format sarif --output aware.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: aware.sarif
```

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor, abra uma issue ou pull request.

---

## 📜 License

MIT License - veja [LICENSE](LICENSE) para detalhes.

---

## 🙏 Créditos

Desenvolvido por **[Vinícius Lisboa](https://viniciuslisboa.com.br)** ([GitHub](https://github.com/IamXeoth))

Parte do ecossistema [Hummand](https://hummand.tech) - GovTech e Soluções Empresariais.

---

## 📫 Contato

- **Email:** contato@viniciuslisboa.com.br
- **GitHub:** [@IamXeoth](https://github.com/IamXeoth)
- **Website:** [viniciuslisboa.com.br](https://viniciuslisboa.com.br)

---

**AWARE** não substitui ferramentas de segurança tradicionais (SAST, SOC).  
Ele complementa reduzindo erro humano **antes** do incidente.