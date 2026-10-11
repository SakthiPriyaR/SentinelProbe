# SentinelProbe - API & LLM Security Scanner

![SentinelProbe Logo](/assets/images/logos/sentinelprobe-3.png)

Automatically Tests for vulnerabilities after generating tests from openapi specification file. Project is in Beta stage, so sometimes it might crash while running.

![UnDocumented petstore API endpoint HTTP method results](/assets/images/tests/sentinelprobe-v0.5.0.png)

## Security Checks

- [x] Restricted HTTP Methods
- [x] SQLi
- [x] BOLA (Might need few bug fixes)
- [x] Data Exposure (Detects Common Data Exposures)
- [x] BOPLA / Mass Assignment
- [x] Broken Access Control
- [x] Basic Command Injection
- [x] Basic XSS/HTML Injection test
- [x] Basic SSTI test
- [ ] Broken Authentication

## Features

- Few Security Checks from OWASP API Top 10
- Automated Testing
- User Config Based Testing
- API for Automating tests and Integrating Tool with other platforms/tools
- CLI tool
- Proxy Support
- Secure Dockerized Project for Easy Usage
- Open Source Tool with MIT License
- Github Action



> Note: The columns for 'data_leak' and 'result' in the table represent independent aspects. It's possible for there to be a data leak in the endpoint, yet the result for that endpoint may still be marked as 'Success'. This is because the 'result' column doesn't necessarily reflect the overall test result; it may indicate success even in the presence of a data leak.

## Github Action

- Create github action secret `url` for your repo
- Setup github action workflow in your repo `.github/workflows/sentinelprobe.yml`

```yml
name: SentinelProbe Sample Workflow

on:
  push:
    branches:
      - dev
      - main

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - name: "download swagger/OAS file"
        run: curl ${url} -o /tmp/swagger.json
        env:
          url: ${{ secrets.url }}

      - name: "SentinelProbe CICD Scanner"
        uses: SakthiPriyaR/sentinelprobe@main # SakthiPriyaR/sentinelprobe@v0.1.0
        with:
          file: /tmp/swagger.json # or ${{ secrets.url }}
          rate_limit: 120
          artifact_retention_days: 1
```

> Prefer locking action to specific version `SakthiPriyaR/sentinelprobe@v0.1.0` instead of using `SakthiPriyaR/sentinelprobe@main` and bump SentinelProbe action version after testing.

## PyPi Downloads

| Period |                                                                                               Count                                                                                                |
| :----: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| Weekly | [![Downloads](https://static.pepy.tech/personalized-badge/sentinelprobe?period=week&units=international_system&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/sentinelprobe)  |
| Monthy | [![Downloads](https://static.pepy.tech/personalized-badge/sentinelprobe?period=month&units=international_system&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/sentinelprobe) |
| Total  | [![Downloads](https://static.pepy.tech/personalized-badge/sentinelprobe?period=total&units=international_system&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/sentinelprobe) |

## Disclaimer

The disclaimer advises users to use the open-source project for ethical and legitimate purposes only and refrain from using it for any malicious activities. The creators and contributors of the project are not responsible for any illegal activities or damages that may arise from the misuse of the project. Users are solely responsible for their use of the project and should exercise caution and diligence when using it. Any unauthorized or malicious use of the project may result in legal action and other consequences.

[Read More](./DISCLAIMER.md)

## Installation
 
### From Source (Recommended until PyPI release)

- Clone and install locally:

    ```bash
    git clone https://github.com/SakthiPriyaR/sentinelprobe.git
    cd sentinelprobe/src
    pip install .          # only cli tool
    pip install ".[api]"    # cli + api server
    ```

- Or install directly using pip from git:

    ```bash
    python3 -m pip install git+https://github.com/SakthiPriyaR/sentinelprobe.git#subdirectory=src
    ```

### Using Containers

### Docker

- Build Image

    ```bash
    make local
    ```

- CLI Tool

  ```bash
  docker run --rm YOUR-DOCKERHUB-USERNAME/sentinelprobe
  ```

- API

  ```bash
  docker compose up -d
  ```

  > POST `openapi` documentation to `/api/v1/scan/` endpoint with its valid `type` (json/yaml); `job_id` will be returned.

### Manual Method

- Open terminal

- Install git package

  ```bash
  sudo apt install git python3 -y
  ```

- Install [Poetry](https://python-poetry.org/docs/master#installing-with-the-official-installer)

- clone the repository to your machine

  ```bash
  git clone https://github.com/SakthiPriyaR/sentinelprobe.git
  ```

- Change directory

  ```bash
  cd sentinelprobe
  ```

- install with poetry

  ```bash
  # without options
  poetry install
  ```

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

## Start SentinelProbe

### API

- Start API Server

  ```bash
  python -m sentinelprobe.api

  # OR

  sentinelprobe-api
  ```

- API Documentation can be found at <http://localhost:8000/docs>

### CLI Tool

- Run sentinelprobe

  ```bash
  sentinelprobe -f swagger_file.json              # using file
  sentinelprobe -f https://example.com/docs.json  # using url
  ```

- To get all the commands use `help`

  ```bash
  sentinelprobe -h
  ```

- Save result in `json`, `yaml` or `html` formats.

  ```bash
  sentinelprobe -f swagger_file.json -o output.json -of html  # json
  sentinelprobe -f swagger_file.json -o output.html -of html  # html
  sentinelprobe -f swagger_file.json -o output.yaml -of yaml  # yaml
  ```

> `json` format is default output format.
> `yaml` format needs to be sanitized before usage since it dumps data as python objects.
> `html` format needs more visualization.

- Run tests only for endpoint paths matching regex pattern

  ```bash
  sentinelprobe -f swagger_file.json -pr '/user'
  ```

- Add headers to requests

  ```bash
  sentinelprobe -f swagger_file.json -H 'Accept: application/json' -H 'Authorization: Bearer YourJWTToken'
  ```

- Run Test with Requests Rate Limited

  ```bash
  sentinelprobe -f swagger_file.json -rl 1000
  ```

  > `rl`: requests rate limit per second

- Use along with proxy

  ```bash
  # without ssl check
  sentinelprobe -f swagger_file.json -p http://localhost:8080 -o output.json -of json # ssl checks are disabled by default to avoid certificate installations

  # with ssl check enforced
  sentinelprobe -f swagger_file.json -p http://localhost:8080 -o output.json -of json --ssl
  ```

  > Make sure that proxy can handle multiple requests at the same time

- Use user provided inputs for generating tests

  ```bash
  sentinelprobe -f swagger_file.json -tdc test_data_config.yaml
  ```

  `test_data_config.yaml`

  ```yaml
  actors:
    - actor1:
      request_headers:
        - name: Authorization
          value: Bearer [Token1]
        - name: User-Agent
          value: sentinelprobe-actor1

      query:
        - name: id
          value: 145
          type: int
        - name: country
          value: uk
          type: str
        - name: city
          value: london
          type: str

      body:
        - name: name
          value: actorone
          type: str
        - name: email
          value: actorone@example.com
          type: str
        - name: phone
          value: +11233211230
          type: str

      unauthorized_endpoints: # For broken access control
        - "/store/order/.*"

    - actor2:
        request_headers:
          - name: Authorization
            value: Bearer [Token2]
          - name: User-Agent
            value: sentinelprobe-actor2

        query:
          - name: id
            value: 199
            type: int
          - name: country
            value: uk
            type: str
          - name: city
            value: leeds
            type: str

        body:
          - name: name
            value: actortwo
            type: str
          - name: email
            value: actortwo@example.com
            type: str
          - name: phone
            value: +41912312311
            type: str
  ```

> If you're using Termux or windows, then use `pip` instead of `pip3`.
> Few features are only for linux os, hence they might not work on windows and require admin priviliges.



## LICENSE

SentinelProbe is distributed under `MIT` License. Refer [License](/LICENSE.md) for more information.
