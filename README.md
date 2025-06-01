# ⚡ VAJRA — Vulnerability Analysis, Judgement & Reporting Arsenal

AI-powered penetration test report generator. Runs 100% locally — no data sent anywhere except your configured AI endpoint.

> **Report Types:** Penetration Test · Red Team · Phishing Campaign  
> **AI Providers:** Claude · ChatGPT · Gemini · Grok · Mistral · Cohere · Groq · Ollama · and more

---

## Quick Start

```bash
# 1. Clone or extract
cd vajra

# 2. Run setup (installs Python + Node deps, creates .env)
bash setup.sh

# 3. Configure your AI provider
nano .env

# 4. Start
python3 app.py

# 5. Open browser
open http://localhost:5000
```

Default login: `admin` / `vajra-admin-2026` — **change this after first login.**

---

## Supported AI Providers

| AI_PROVIDER | Service | Default Model | Notes |
|---|---|---|---|
| `anthropic` | Anthropic Claude | `claude-sonnet-4-6` | Default. Direct or proxy. |
| `openai` | OpenAI ChatGPT | `gpt-4o` | Any OpenAI-spec endpoint. |
| `gemini` | Google Gemini | `gemini-1.5-pro` | Requires `google-generativeai` |
| `grok` | xAI Grok | `grok-2` | Auto-routes to `api.x.ai` |
| `mistral` | Mistral AI | `mistral-large-latest` | Requires `mistralai` |
| `cohere` | Cohere Command | `command-r-plus` | Requires `cohere` |
| `groq` | Groq inference | `llama-3.3-70b-versatile` | Very fast. Auto-routes. |
| `together` | Together AI | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | Auto-routes. |
| `openrouter` | OpenRouter | any | 200+ models. Auto-routes. |
| `ollama` | Ollama (local) | `llama3.1:70b` | No key needed. |
| `deepseek` | DeepSeek | `deepseek-chat` | Auto-routes. |

---

## Provider Configuration

Set these in your `.env` file. Only `AI_PROVIDER`, `AI_API_KEY`, and `AI_MODEL` are required — `AI_BASE_URL` is optional for providers with a built-in default.

### Anthropic (Claude)
```env
AI_PROVIDER=anthropic
AI_API_KEY=sk-ant-your-key-here
AI_BASE_URL=https://api.anthropic.com
AI_MODEL=claude-sonnet-4-6
```

### OpenAI (ChatGPT)
```env
AI_PROVIDER=openai
AI_API_KEY=sk-your-openai-key
AI_MODEL=gpt-4o
```

### Google Gemini
```bash
pip3 install google-generativeai --break-system-packages
```
```env
AI_PROVIDER=gemini
AI_API_KEY=AIza-your-google-ai-key
AI_MODEL=gemini-1.5-pro
```

### xAI Grok
```env
AI_PROVIDER=grok
AI_API_KEY=xai-your-key-here
AI_MODEL=grok-2
```

### Mistral AI
```bash
pip3 install mistralai --break-system-packages
```
```env
AI_PROVIDER=mistral
AI_API_KEY=your-mistral-key
AI_MODEL=mistral-large-latest
```

### Cohere
```bash
pip3 install cohere --break-system-packages
```
```env
AI_PROVIDER=cohere
AI_API_KEY=your-cohere-key
AI_MODEL=command-r-plus
```

### Groq (fast inference)
```env
AI_PROVIDER=groq
AI_API_KEY=gsk_your-groq-key
AI_MODEL=llama-3.3-70b-versatile
```

### Together AI
```env
AI_PROVIDER=together
AI_API_KEY=your-together-key
AI_MODEL=meta-llama/Llama-3.3-70B-Instruct-Turbo
```

### OpenRouter (200+ models)
```env
AI_PROVIDER=openrouter
AI_API_KEY=sk-or-your-key
AI_MODEL=anthropic/claude-3.5-sonnet
```

### Ollama (local, free, no key)
```bash
ollama pull llama3.1:70b
```
```env
AI_PROVIDER=ollama
AI_API_KEY=not-required
AI_BASE_URL=http://localhost:11434/v1
AI_MODEL=llama3.1:70b
```

### DeepSeek
```env
AI_PROVIDER=deepseek
AI_API_KEY=your-deepseek-key
AI_MODEL=deepseek-chat
```

### Self-hosted proxy (LiteLLM, vLLM, Azure OpenAI, etc.)
```env
AI_PROVIDER=openai          # or anthropic — match the proxy's wire format
AI_API_KEY=your-proxy-token
AI_BASE_URL=https://your-gateway.example.com/v1
AI_MODEL=your-model-name
SKIP_SSL_VERIFY=true        # if using self-signed TLS cert
```

---

## Adding a New Provider

1. Open `app.py` and find the `_call_provider()` function.
2. Add a new `elif p == "your_provider":` branch with the provider's SDK call.
3. Add its default base URL to `_OPENAI_COMPAT_PROVIDERS` if it's OpenAI-compatible.
4. Set `AI_PROVIDER=your_provider` in `.env`.

---

## Folder Structure

```
vajra/
├── app.py                     # Flask backend
├── .env                       # Your config (never commit this)
├── .env.example               # Config template with all provider examples
├── requirements.txt
├── setup.sh
├── Dockerfile
│
├── docx_builder/              # DOCX / PDF export engine
│   ├── generate.js
│   ├── generate-pdf.js
│   ├── cover_generator.py
│   └── docx_template_filler.py
│
├── knowledge/                 # AI context — drop .md/.txt files here
│   ├── kb-core-reference.md
│   ├── kb-web-application.md
│   ├── kb-active-directory.md
│   └── ...
│
├── custom_templates/          # Report templates (.docx or .md)
│
├── ui/
│   ├── templates/             # HTML pages
│   └── static/logos/          # Company / tester logos
│
├── reports/                   # Generated files
└── database/
    └── penreport.db
```

---

## Features

| Feature | Details |
|---|---|
| **Report Types** | Penetration Test · Red Team · Phishing Campaign |
| **Finding Input** | Paste notes · Manual form · Tool import (Nessus, Burp, Nmap XML) |
| **Large Assessments** | Parallel chunked generation for 10+ findings |
| **Export** | DOCX · PDF · Markdown |
| **Custom Templates** | Upload `.docx` or `.md` templates |
| **Knowledge Base** | Drop `.md`/`.txt` into `knowledge/` — auto-loaded as AI context |
| **Team Access** | Multi-user with roles: admin · analyst · viewer |
| **Report Sharing** | Per-report visibility + explicit user sharing |
| **Logos** | Company and tester logos embedded in DOCX cover |

---

## PDF Export

VAJRA tries multiple PDF backends automatically (LibreOffice → pandoc → weasyprint).  
Easiest to install:

```bash
pip3 install weasyprint markdown --break-system-packages
```

---

## Docker Deployment

```bash
docker build -t vajra .
docker run -p 5000:5000 --env-file .env vajra
```

---

## Security Notes

- Runs on `localhost` by default. Set `HOST=0.0.0.0` only on a trusted network.
- Set a strong `SECRET_KEY` in `.env` before team deployment.
- Never commit `.env` to version control — it contains your API key.
- Change the default admin password immediately after first login.
