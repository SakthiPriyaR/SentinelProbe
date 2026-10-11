# SentinelProbe

SentinelProbe is a security scanner for modern API and AI-powered applications. It automatically tests REST APIs for common vulnerabilities by generating tests from an OpenAPI/Swagger specification, with automatic input fuzzing and user-supplied inputs via a YAML config file. It can also scan LLMs for vulnerabilities (prompt injection, jailbreaks, and more) through [NVIDIA garak](https://github.com/NVIDIA/garak).

![UnDocumented petstore API endpoint HTTP method results](assets/images/tests/sentinelprobe-v0.5.0.png)



## Security Checks

-   Restricted HTTP Methods
-   SQLi
-   BOLA
-   Data Exposure
-   BOPLA / Mass Assignment
-   Broken Access Control
-   Basic Command Injection
-   Basic XSS/HTML Injection test

## Features

-   Few Security Checks from OWASP API Top 10
-   Automated Testing
-   User Config Based Testing
-   API for Automating tests and Integrating Tool with other platforms/tools
-   CLI tool
-   LLM vulnerability scanning via NVIDIA garak (optional)
-   Dockerized Project for Easy Usage
-   Open Source Tool with MIT License

## LLM Scanning (NVIDIA garak)

SentinelProbe can scan LLMs for vulnerabilities (prompt injection, jailbreaks, encoding bypasses, toxicity, data leakage and more) by running [NVIDIA garak](https://github.com/NVIDIA/garak) and turning its report into SentinelProbe's json / yaml / html / table output.

> **Authorization:** only scan models and endpoints you own or have written permission to test. garak sends many adversarial prompts, which can cost money and may trigger provider abuse monitoring.

garak is optional and is run as a subprocess, so install it separately:

```bash
pip install garak
```

Credentials are read by garak from the environment (for example `OPENAI_API_KEY`); SentinelProbe never stores or logs them.

```bash
# list the probes garak offers
sentinelprobe --llm-list-probes

# scan only an LLM (a probe list is required, because garak runs every probe by default)
export OPENAI_API_KEY=...
sentinelprobe --mode llm --llm-model-type openai --llm-model-name gpt-4o-mini \
  --llm-probes promptinject,dan -o llm-report.html

# scan an API and an LLM in one run (API report -> report.json, LLM report -> report.llm.json)
sentinelprobe --mode all -f openapi.json \
  --llm-model-type openai --llm-model-name gpt-4o-mini --llm-probes dan -o report.json
```

| Option | Purpose |
| --- | --- |
| `--mode {api,llm,all}` | what to scan (default `api`) |
| `--llm-model-type` | garak generator type: `openai`, `huggingface`, `ollama`, `rest`, ... |
| `--llm-model-name` | model name for that generator |
| `--llm-probes` | comma separated probes or probe modules (required for `llm`/`all`) |
| `--llm-generations`, `--llm-parallel-attempts`, `--llm-seed` | passed to garak |
| `--llm-generator-options` | garak generator options JSON file (needed for the `rest` generator) |
| `--llm-timeout` | max seconds for garak (default 3600) |
| `--llm-report-dir` | where the raw garak report is kept (default `sentinelprobe_llm_runs`) |

How results are read: garak detector scores above 0.5 count as a successful attack, so a probe is marked `VULNERABLE` when at least one attempt succeeded. The raw garak `*.report.jsonl` is always kept, and its path is logged.

## Safety and CI options

| Option | Purpose |
| --- | --- |
| `--safe` | only send `GET`, `HEAD` and `OPTIONS` (no state-changing requests) |
| `--fail-on-vuln` | exit with code `2` when a vulnerability is found, so CI pipelines can fail |

Exit codes: `0` clean, `1` scan could not run (bad file, host down, garak error), `2` vulnerabilities found with `--fail-on-vuln`.

**API server:** `AUTH_SECRET_KEY` must be set (a random one is generated otherwise and cannot be shared with other clients). Direct loopback requests are trusted; anything else must send it in a `SECRET-KEY` header. The `openapi` field accepts a URL or an inline spec, never a server file path, and link-local/cloud-metadata addresses are refused as targets.

## Roadmap

-   [x] Integrate [NVIDIA garak](https://github.com/NVIDIA/garak) (LLM vulnerability scanner) as an LLM-probing module
-   [x] CLI option to choose scan mode: `api`, `llm`, or `all`
-   [ ] One combined report for API and LLM findings (currently two separate reports)
-   [x] LLM scanning through the REST API server (`sentinelprobe-api`)
-   [ ] LLM scanning in the GitHub Action

## Installation (from Source)

Until SentinelProbe is published on PyPI, install from source:

```bash
# Clone the repository
git clone https://github.com/SakthiPriyaR/sentinelprobe.git
cd sentinelprobe/src

# Install locally
pip install .          # CLI only
pip install ".[api]"    # CLI + API server
```

Or install directly via pip from Git:

```bash
pip install git+https://github.com/SakthiPriyaR/sentinelprobe.git#subdirectory=src
```

-   Run Tool

```bash
sentinelprobe -f swagger_file.json
```

-   For more usage options read [README.md](https://github.com/SakthiPriyaR/sentinelprobe/blob/main/src/README.md)

