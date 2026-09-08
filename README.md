# Egyxos Scanner

**Egyxos** is a modular, Linux-friendly security reconnaissance CLI. It
provides one consistent command interface for authorized asset discovery,
HTTP enrichment, crawling, URL and parameter discovery, service enumeration,
and non-destructive vulnerability detection.

It normalizes scanner output into terminal, JSON, CSV, HTML, and SARIF reports
and handles optional external tools without silently hiding missing
dependencies.

> **Authorized use only.** Scan only systems you own or have explicit
> permission to assess. Egyxos does not provide exploit execution, credential
> attacks, destructive testing, persistence, evasion, or unauthorized access.
> SQLmap is always a separate explicit opt-in operation.

## Install and use

### Requirements

- Linux, WSL, or a Linux server
- Python 3.9 or newer
- Git
- Optional scanner tools for individual modules

### Install from Git

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/zezo7amaad/Egyxos-Scanner.git
cd Egyxos-Scanner

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Verify the installation:

```bash
egyxos --version
egyxos --help
egyxos tools check
```

For development installation, use:

```bash
python -m pip install -e .
```

### Install optional scanner tools

The base package uses only the Python standard library. External tools are
detected at runtime and missing tools are reported clearly.

```bash
sudo apt install -y nmap golang-go
mkdir -p "$HOME/go/bin"
export PATH="$HOME/go/bin:$PATH"

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

egyxos tools check
```

Additional integrations include ParamSpider, Arjun, FFUF, and SQLmap. Install
them separately according to their official documentation when required.

### Run a first scan

Only use a target you are authorized to test. The `--yes` flag confirms that
authorization is present:

```bash
egyxos scan example.com \
  --yes \
  --profile passive \
  --format html \
  --output-dir results
```

The equivalent explicit authorization flag is:

```bash
egyxos scan example.com --yes-i-am-authorized --profile passive
```

Available profiles:

| Profile | Purpose |
| --- | --- |
| `passive` | Lower-impact discovery and enrichment |
| `standard` | Broader discovery, crawling, services, and checks |
| `deep` | Additional crawling and explicitly controlled modules |

Private and loopback targets require the additional `--allow-private` flag:

```bash
egyxos http 127.0.0.1:8000 --yes --allow-private
```

### Run individual modules

```bash
egyxos subdomains example.com --yes
egyxos http example.com --yes
egyxos crawl https://example.com --yes
egyxos urls example.com --yes
egyxos params example.com --yes
egyxos ports example.com --yes
egyxos vuln example.com --yes
```

Controlled content discovery requires an explicit URL and wordlist:

```bash
egyxos fuzz https://example.com/FUZZ \
  --yes \
  --wordlist /path/to/wordlist.txt
```

SQL injection testing is never included automatically:

```bash
egyxos sqli "https://authorized.example/item?id=1" \
  --yes \
  --i-understand-sqlmap
```

### Reports and output

Full scans create timestamped directories:

```text
results/
└── example.com/
    └── 2026-09-08_133500/
        ├── result.json
        ├── report.html
        └── egyxos.log
```

Supported formats are `terminal`, `json`, `csv`, `html`, and `sarif`:

```bash
egyxos scan example.com --yes --format json
egyxos report results/example.com/TIMESTAMP --format html --output report.html
egyxos report results/example.com/TIMESTAMP --format sarif --output report.sarif
```

### Configuration

Create and inspect the default configuration:

```bash
egyxos config init
egyxos config show
egyxos config path
```

The default file is:

```text
~/.config/egyxos/config.toml
```

Set `EGYXOS_CONFIG` or `XDG_CONFIG_HOME` to use a different location. Do not
store credentials, API tokens, cookies, or authorization headers in the
configuration file.

## Command reference

```text
egyxos scan <target>       Complete authorized assessment
egyxos recon <target>      Reconnaissance pipeline
egyxos subdomains <target> Subdomain enumeration
egyxos http <target>       HTTP probing and enrichment
egyxos crawl <target>      Controlled web crawling
egyxos urls <target>       URL discovery
egyxos params <target>     Parameter discovery
egyxos fuzz <url/FUZZ>     Controlled content discovery
egyxos ports <target>      Service enumeration
egyxos vuln <target>       Non-destructive vulnerability checks
egyxos sqli <url>          Explicit SQL injection testing
egyxos report <directory>  Regenerate reports
egyxos tools check         Check optional dependencies
egyxos config show         Show configuration
egyxos version             Show the installed version
```

Use `egyxos <command> --help` for command-specific options such as
`--threads`, `--timeout`, `--rate-limit`, `--scope-file`, `--quiet`, and
`--verbose`.

## Run online with GitHub Actions

The repository includes
[`.github/workflows/EgyxosScan.yaml`](.github/workflows/EgyxosScan.yaml).
It installs and runs the Python CLI on a GitHub-hosted Linux runner and uploads
reports as workflow artifacts.

### Manual workflow run

1. Open the repository's **Actions** tab.
2. Select **Egyxos Authorized Scan**.
3. Select **Run workflow**.
4. Enter a target you are authorized to test.
5. Choose `passive`, `standard`, or `deep`.
6. Choose the report format.
7. Download the generated artifact from the completed workflow.

The workflow intentionally has no scheduled trigger. It runs only when you
select **Run workflow** manually, so every scan target and profile is chosen
by the operator at launch time.

Keep this workflow protected from untrusted users. Never accept arbitrary scan
targets from public pull requests or expose the scanner through an
unauthenticated web endpoint.

## Run with Docker

Build the image locally from the repository root. The image installs the
Egyxos CLI together with Nmap, SQLmap, Subfinder, HTTPX, Katana, Nuclei, FFUF,
ParamSpider, and Arjun:

```bash
docker build -t egyxos-scanner .
```

Verify the CLI and bundled toolchain:

```bash
docker run --rm egyxos-scanner tools check
```

Run an authorized scan and keep reports on the host. The host directory is
mounted at `/app/results` inside the container:

```bash
mkdir -p results
docker run --rm \
  -v "$(pwd)/results:/app/results" \
  egyxos-scanner scan example.com \
  --yes \
  --format html \
  --output-dir /app/results
```

If a port scan uses Nmap raw-packet/SYN scanning, grant only the capabilities
required by that authorized operation:

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  egyxos-scanner ports example.com --yes
```

The published image is available from GitHub Container Registry after a
release workflow completes:

```bash
docker pull ghcr.io/zezo7amaad/egyxos-scanner:latest
docker run --rm ghcr.io/zezo7amaad/egyxos-scanner:latest tools check
```

The image is intended for authorized assessments. Do not expose it as an
unauthenticated public scanning service or accept arbitrary targets from
untrusted users.

## Development and testing

```bash
python -m pip install -e .
python -m pytest -q
python -m egyxos --help
python -m egyxos tools check
```

External commands are executed with argument lists rather than shell
interpolation, enforce timeouts, support cancellation, and return structured
errors for missing tools or malformed output.
