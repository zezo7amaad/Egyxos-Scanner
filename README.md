# Egyxos

Egyxos is a modular, Linux-friendly Python security reconnaissance CLI. It
normalizes output from common security tools and can write terminal, JSON,
CSV, HTML, or SARIF reports.

> **Authorization:** Use Egyxos only on systems you own or are explicitly
> authorized to test. Every active scanner requires an explicit
> `--yes-i-am-authorized` confirmation (or `EGYXOS_AUTHORIZED=1`). Private and
> loopback targets additionally require `--allow-private`. SQLmap is disabled
> unless it is explicitly opted into.

## Install and use

```bash
python -m pip install -e .
egyxos --help
egyxos version
egyxos tools
egyxos subdomains example.com --yes-i-am-authorized --format json
egyxos recon example.com --yes-i-am-authorized --output report.json --format json
egyxos report report.json --format sarif --output report.sarif
```

The base package uses only the Python standard library. External tools are
optional and are detected at runtime; missing tools produce structured errors
instead of unsafe fallbacks. Commands are passed as argv lists (never through a
shell), have timeouts and support cancellation.

## Commands

`scan`/`recon`, `subdomains`, `http`, `crawl`, `urls`, `params`, `fuzz`,
`ports`, `vuln`, `sqli`, `report`, `tools`, `config`, and `version` are
available. Integrations cover Subfinder, HTTPX, Katana, ParamSpider, Arjun,
FFUF, Nmap, Nuclei, and SQLmap. Fuzzing requires an explicit `--wordlist`.

Configuration is read from `$EGYXOS_CONFIG` or
`$XDG_CONFIG_HOME/egyxos/config.toml`:

```bash
egyxos config init
egyxos config show
```

## Development

```bash
python -m pytest
python -m egyxos --help
```

The existing GitHub Actions scanner remains available for Discord-compatible
scheduled workflows; the Python CLI is suitable for local use and CI artifacts.

## Run online with GitHub Actions

The repository includes `.github/workflows/EgyxosScan.yaml`, which runs the
Python CLI on a GitHub-hosted Linux runner and uploads reports as workflow
artifacts. For a manual scan, open **Actions → Egyxos Authorized Scan → Run
workflow**, enter an authorized target, and choose a profile and report format.

For scheduled scans, create the repository variable `EGYXOS_TARGET` under
**Settings → Secrets and variables → Actions → Variables**. Optionally set
`EGYXOS_PROFILE` to `passive`, `standard`, or `deep`. Scheduled scans use the
configured target and upload results for 14 days. Do not expose this workflow
to untrusted contributors or accept arbitrary targets from public pull
requests.
