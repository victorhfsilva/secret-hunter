# secret-hunter

**secret-hunter** é um rastreador de segredos/credenciais para aplicações web,
escrito em Python, para uso em testes de segurança autorizados. Ele rastreia
páginas HTML e arquivos JavaScript, extrai candidatos a segredos por meio de um
catálogo de padrões de expressões regulares, e opcionalmente enriquece cada
candidato com uma classificação feita por um modelo de linguagem (LLM) dos
provedores **Verboo**, **OpenRouter** ou **Ollama**.

Diferentemente de ferramentas de enumeração de subdomínios (como `dnsx`),
`secret-hunter` **não resolve nem força subdomínios via DNS**. Ele faz apenas
requisições HTTP(S) às sementes fornecidas e segue links e referências de
JavaScript *dentro do escopo*. Isso o torna confiável quando executado atrás de
uma VPN como **Mullvad**, onde a enumeração baseada em DNS costuma ser
instável, mas o tráfego HTTP normal funciona.

---

## Índice

- [Por que HTTP apenas (e por que isso combina com Mullvad)](#por-que-http-apenas-e-por-que-isso-combina-com-mullvad)
- [O que ele faz](#o-que-ele-faz)
- [Recursos](#recursos)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Provedores de IA](#provedores-de-ia)
- [Referência de opções](#referência-de-opções)
- [Formato do relatório](#formato-do-relatório)
- [Catálogo de padrões](#catálogo-de-padrões)
- [Segurança e uso autorizado](#segurança-e-uso-autorizado)
- [Perguntas frequentes](#perguntas-frequentes)

---

## Por que HTTP apenas (e por que isso combina com Mullvad)

Ferramentas clássicas de reconhecimento web costumam combinar varredura HTTP
com **enumeração de subdomínios por DNS** (`dnsx`, `subfinder`, etc.). Essa
parte DNS é exatamente o que quebra quando a saída de rede passa por uma VPN
como a Mullvad:

- a resolução de subdomínios wildcard e a descoberta passiva ficam lentas ou
  retornam respostas inconsistentes;
- muitos provedores de DNS públicos filtram ou bloqueiam consultas em volume;
- a VPN pode rotear o DNS de forma que a resolução falhe para registros
  recém-criados ou para zonas que dependem de resolução local.

`secret-hunter` resolve esse problema de forma direta: **não existe código de
enumeração DNS**. O escopo é definido apenas pela string da URL (esquema +
domínio registrável), e toda a descoberta é feita por requisições HTTP(S) reais
— exatamente o tipo de tráfego que a Mullvad encaminha sem problemas.

---

## O que ele faz

O fluxo de trabalho é dividido em quatro etapas:

1. **Rastreamento (crawl)** — a partir de uma ou mais URLs semente, busca cada
   página, extrai links (`href`/`src`/`action`), segue-os até uma profundidade
   configurável, e baixa os arquivos JavaScript referenciados. Também detecta e
   baixa `source maps` (`.js.map`) referenciados nos arquivos JS, pois eles
   costumam conter código-fonte original com segredos.
2. **Extração** — o catálogo de expressões regulares é aplicado a todo o texto
   coletado (HTML + JS + source maps). Cada correspondência vira um candidato
   com tipo, valor, trecho de código (snippet), origem, linha/coluna e entropia
   de Shannon. Heurísticas filtram falsos positivos óbvios (placeholders,
   `example`, `test`, valores de baixa entropia, referências a variáveis de
   ambiente).
3. **Classificação por IA (opcional)** — se um provedor de IA estiver
   configurado, cada candidato é analisado por um LLM, que devolve gravidade
   (Critical/High/Medium/Low/Informational/FalsePositive), pontuação de 0 a 10,
   se é reportável, impacto, correção sugerida, CWE e uma explicação. O valor
   do segredo é **mascarado antes de ser enviado** ao provedor, para que a
   credencial bruta não saia da máquina local quando um provedor remoto
   (Verboo/OpenRouter) é usado.
4. **Relatório** — os resultados são ordenados (reportáveis primeiro, depois
   por pontuação) e gravados em JSON, além de um resumo legível no terminal.

---

## Recursos

- **Catálogo com dezenas de padrões**, cobrindo AWS, GCP, Azure, GitHub,
  GitLab, Slack, Discord, OpenAI, Anthropic, Stripe, PayPal, MongoDB,
  PostgreSQL, MySQL, Redis, JWT, chaves privadas PEM, e muitos outros tipos.
- **Rastreamento com escopo por URL**, sem enumeração DNS.
- **Profundidade, limite de URLs e concorrência configuráveis.**
- **Coleta de source maps** para expor código-fonte original.
- **Suporte a cookies, cabeçalhos customizados e proxy** (útil para rotas de
  residencial ou para contornar restrições geográficas).
- **Classificação opcional por LLM** com três provedores: Verboo, OpenRouter e
  Ollama.
- **Validação opcional** (`--validate`) de alguns tipos de token contra APIs
  reais, somente leitura.
- **Saída em JSON** e **resumo em texto**.
- **Tolerante a falhas**: se o provedor de IA estiver fora do ar, a varredura
  continua e os candidatos ficam marcados como "Informational".

---

## Requisitos

- Python 3.10 ou superior (testado em 3.14).
- A biblioteca `requests` (listada em `requirements.txt`).
- Opcional: `boto3` apenas se você quiser validar chaves de acesso AWS com
  `--validate`.

---

## Instalação

Clone/copie a pasta e instale a dependência:

```bash
cd /opt/secret-hunter
pip install -r requirements.txt
```

Nenhum passo extra é necessário para o modo somente-regex. Para usar a
classificação por IA, configure o provedor desejado (ver abaixo).

---

## Uso

A forma mais simples é fornecer uma URL ou um hostname de semente:

```bash
# Varredura rápida, somente regex (sem LLM)
python3 secret-hunter.py https://exemplo.com

# Hostname simples (será tratado como https://)
python3 secret-hunter.py exemplo.com

# Várias sementes
python3 secret-hunter.py https://a.com https://b.com

# Com classificação por IA usando Ollama (padrão)
python3 secret-hunter.py https://exemplo.com --provider ollama
```

Para salvar o relatório em JSON e suprimir o resumo:

```bash
python3 secret-hunter.py https://exemplo.com --no-llm -o resultado.json --quiet
```

---

## Provedores de IA

`secret-hunter` usa um único cliente compatível com a API
`/chat/completions` do OpenAI. Os três provedores suportados diferem apenas no
endpoint, na chave e no modelo padrão.

### 1. Ollama (local)

Ideal para rodar 100% local, sem enviar dados para fora.

```bash
# Modelo padrão: qwen2.5-coder:7b
python3 secret-hunter.py https://exemplo.com --provider ollama

# Personalizar
python3 secret-hunter.py https://exemplo.com \
  --provider ollama --base-url http://localhost:11434 \
  --model qwen2.5-coder:7b
```

### 2. OpenRouter

Um gateway que dá acesso a vários modelos com uma única chave.

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
python3 secret-hunter.py https://exemplo.com --provider openrouter
```

### 3. Verboo

O `secret-hunter` trata o Verboo como um endpoint compatível com OpenAI.
Como o endpoint exato pode variar, configure-o por variáveis de ambiente (ou
por flags):

```bash
export VERBOO_BASE_URL="https://seu-endpoint-verboo/v1"
export VERBOO_API_KEY="sua-chave"
export VERBOO_MODEL="seu-modelo"
python3 secret-hunter.py https://exemplo.com --provider verboo
```

### Configuração por variáveis de ambiente

Você pode definir o provedor e seus parâmetros sem flags:

| Variável | Descrição |
|----------|-----------|
| `SECRET_HUNTER_PROVIDER` | `verboo` \| `openrouter` \| `ollama` |
| `SECRET_HUNTER_BASE_URL` | Base URL do provedor (esquema + host) |
| `SECRET_HUNTER_API_KEY` | Chave bearer (Verboo / OpenRouter) |
| `SECRET_HUNTER_MODEL` | Nome do modelo |
| `SECRET_HUNTER_TIMEOUT` | Timeout por requisição (padrão `120`) |
| `VERBOO_BASE_URL` / `VERBOO_API_KEY` / `VERBOO_MODEL` | Sobrescreve para Verboo |
| `OPENROUTER_BASE_URL` / `OPENROUTER_API_KEY` / `OPENROUTER_MODEL` | Sobrescreve para OpenRouter |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | Sobrescreve para Ollama |

As flags de linha de comando (`--base-url`, `--api-key`, `--model`,
`--provider`) têm precedência sobre as variáveis de ambiente.

---

## Referência de opções

| Opção | Padrão | Descrição |
|-------|--------|-----------|
| `targets` (posicional) | — | URL(s) ou hostname(s) semente. |
| `--provider` | env/`ollama` | `verboo`, `openrouter` ou `ollama`. |
| `--base-url` | — | Sobrescreve a base URL do provedor. |
| `--api-key` | — | Sobrescreve a chave do provedor. |
| `--model` | — | Sobrescreve o modelo. |
| `--no-llm` | `false` | Pula a classificação por IA (somente regex). |
| `--validate` | `false` | Valida alguns tipos de token contra APIs reais (somente leitura). |
| `--depth` | `2` | Profundidade do rastreamento. |
| `--max-urls` | `200` | Número máximo de URLs a buscar. |
| `--concurrency` | `8` | Requisições paralelas. |
| `--timeout` | `15` | Timeout por requisição (segundos). |
| `--same-root` | `false` | Permite rastrear subdomínios irmãos do mesmo domínio registrável. |
| `--no-sourcemaps` | `false` | Não baixa `.js.map` referenciados. |
| `--user-agent` | — | User-Agent customizado. |
| `-H` / `--header` | — | Cabeçalho extra `Nome: valor` (repetível). |
| `--cookie` | — | String de cookie enviada em todas as requisições. |
| `--proxy` | — | Proxy HTTP(S) para todas as requisições. |
| `-o` / `--output` | — | Grava o relatório JSON neste caminho. |
| `--quiet` | `false` | Suprime o resumo no terminal. |

---

## Formato do relatório

O JSON contém metadados e uma lista ordenada de `findings`:

```json
{
  "tool": "secret-hunter",
  "version": "1.0.0",
  "generated_at": "2026-10-26T09:00:00+00:00",
  "targets": ["https://exemplo.com"],
  "provider": "ollama",
  "pages_fetched": 42,
  "candidates_found": 7,
  "errors": [],
  "findings": [
    {
      "type": "OpenAI Key",
      "category": "api_key",
      "value": "sk-proj-...",
      "masked": "sk-p████████████XXXX",
      "entropy": 5.38,
      "source": "https://exemplo.com/app.js",
      "line": 12,
      "column": 9,
      "snippet": "const key = \"sk-proj-...\";",
      "analysis": {
        "criticality": "High",
        "score": 8.3,
        "reportable": true,
        "impact": "...",
        "remediation": "...",
        "cwe": "CWE-798",
        "explanation": "..."
      }
    }
  ]
}
```

O resumo em texto (exibido no terminal) lista a gravidade, pontuação, tipo,
valor mascarado, origem e, quando disponível, explicação, impacto e correção.

---

## Catálogo de padrões

O catálogo está em `secret_hunter/patterns.py` e inclui (entre outros):

- **Nuvem/Infra**: AWS Access Key, AWS Secret Key, AWS Session Token, AWS ARN,
  AWS Cognito Pool ID, AWS S3 URL, GCP API Key, GCP Service Account, Google
  OAuth Token, Google Maps API Key, Azure Client Secret, Azure SAS Token,
  Azure Storage Key, DigitalOcean, Cloudflare, New Relic, Datadog, Heroku,
  Sentry, Twilio, Vercel, Firebase.
- **IA/ML**: OpenAI, Anthropic, Hugging Face, Groq, Replicate, Mistral, Cohere,
  Together, Perplexity, xAI/Grok, OpenRouter.
- **Autenticação/Sessão**: GitHub PAT (clássico e fine-grained), GitLab, Slack,
  Discord, Clerk, Supabase, Auth0, Okta, Grafana.
- **Pagamentos/Finanças**: Stripe (secret e publishable), PayPal, Square,
  Adyen, Braintree.
- **Bancos de dados**: MongoDB, PostgreSQL, MySQL, Redis, SQL Server.
- **Genéricos**: JWT, Bearer Token, Basic Auth, chave privada PEM,
  cabeçalho `Authorization`, Google OAuth Client ID.

Cada candidato passa por heurísticas que descartam valores que parecem
placeholders, testes, exemplos ou constantes de build.

---

## Segurança e uso autorizado

- **Use apenas em alvos que você possui ou para os quais tem autorização
  explícita.** Este é um scanner de segurança; a execução não autorizada é
  ilegal em muitas jurisdições.
- O modo `--validate` faz chamadas somente leitura a APIs de terceiros. Ele é
  opcional e desativado por padrão.
- Os valores de segredos são **mascarados antes de serem enviados ao provedor
  de IA** (exceto no relatório local, onde o valor completo é gravado para que
  você possa agir). Para varredura totalmente offline, use `--provider ollama`
  ou `--no-llm`.

---

## Perguntas frequentes

**Por que não funciona com `dnsx` / enumeração de subdomínios?**
Porque `secret-hunter` não faz enumeração DNS por design. Ele rastreia apenas
o que já é conhecido (as sementes) e o que é descoberto por links/JS. Isso é
intencional para funcionar atrás de VPNs como a Mullvad.

**O provedor de IA caiu. A varredura quebra?**
Não. A classificação falha de forma "aberta": cada candidato recebe
`criticality: Informational` com a mensagem de que a classificação não
retornou, e o restante do relatório é gerado normalmente.

**Como mudo o escopo para incluir subdomínios irmãos?**
Use `--same-root`. Isso permite rastrear hosts que compartilham o mesmo
domínio registrável (ex.: `app.exemplo.com` e `api.exemplo.com`), ainda sem
qualquer resolução DNS adicional.

**O valor do segredo aparece no relatório JSON?**
Sim, o relatório local contém o valor completo (campo `value`) para que você
possa agir, além do campo mascarado `masked`. Se precisar de um relatório
sem os valores, use o campo `masked` ou remova `value` ao pós-processar.
