🛡️ Egyxos Scanner: Advanced Recon & Vulnerability Monitor

Automate your professional reconnaissance and vulnerability scanning pipeline using GitHub Actions. This repository provides an integrated security workflow inspired by professional Bug Bounty methodologies.

Egyxos Scanner combines subdomain discovery, parameter mining, OS fingerprinting, and vulnerability scanning into a single, automated CI/CD pipeline that reports directly to your Discord SOC (Security Operations Center).

🚀 Features

🧭 Advanced Reconnaissance

Continuous Monitoring: Runs every 6 hours (configurable via cron) or manually via ```workflow_dispatch```.

Subdomain Discovery: Uses Subfinder for fast, multi-source subdomain enumeration.

Parameter Mining: Integrates ParamSpider to find URLs with parameters and Arjun to brute-force hidden parameters.

Deep Scanning: Uses Nmap with ```sudo``` privileges for Service Versioning and OS Fingerprinting (IP & OS Detection).

🧨 Vulnerability Assessment

Automated Scanning: Runs Nuclei on all discovered subdomains to identify security issues.

Severity Filtering: Automatically filters for ```critical```, ```high```, and ```medium```vulnerabilities.

Smart Notifications: Generates detailed Discord embed notifications with color-coded alerts (Green for Recon, Red for Vulnerabilities).

Artifact Management: Automatically uploads scan results (```subdomains.txt```, ```nmap_results.txt```, ```nuclei_results.txt```, etc.) to GitHub Actions for manual review.

🛠️ Requirements

A GitHub repository (Private recommended).

GitHub Actions enabled.

Secrets configured in your repository:

```DISCORD_WEBHOOK```: Your Discord channel webhook URL.

⚙️ Setup

Clone/Copy the Workflow:
Place the workflow file in your repository at: ```.github/workflows/EgyxosScan.yaml```

Configure Discord Webhook:

Go to your Discord Server Settings → Integrations → Webhooks.

Create a New Webhook and copy the URL.

In your GitHub Repo, go to Settings → Secrets and variables → Actions.

Click New repository secret.

Name: ```DISCORD_WEBHOOK```

Value: ```https://discord.com/api/webhooks/your_id/your_token```

(Optional) Adjust Schedule:
In EgyxosScan.yaml, modify the cron line to change the frequency:
```
- cron: '0 */6 * * *' # Every 6 hours
```

🔧 Manual Execution

You can trigger a scan for any specific target at any time:

Go to the Actions tab in your GitHub repository.

Select Egyxos Scanner from the left sidebar.

Click the Run workflow dropdown.

Enter the target domain (e.g., ```example.com```) and click Run workflow.

📊 Example Discord Notifications

🔍 Recon Summary Embed

Egyxos Recon Finished
Target: example.com
IP & OS Summary:
```
Nmap scan report for sub.example.com (192.168.1.1)
OS details: Linux 5.x | Ubuntu 22.04
Service: nginx 1.18.0
```

🚨 Vulnerability Alert

Vulnerabilities Detected!
Target: example.com
Nuclei Findings:
```
[critical] CVE-2023-XXXXX - [https://sub.example.com/exploit](https://sub.example.com/exploit)
[high] Exposed .env file - [https://sub.example.com/.env](https://sub.example.com/.env)
```
```
🧩 Tools Integrated

Tool

Description

Subfinder

Passive/Active Subdomain enumeration.

ParamSpider

Extracts parameters from web archives for the target.

Arjun

Finds hidden HTTP parameters using brute force.

Nmap

Network discovery, OS fingerprinting, and Version detection.

Nuclei
```
Template-based vulnerability scanner for modern stacks.

📦 Artifacts

After each run, GitHub Actions will upload the following files. You can download these under the Artifacts section of the workflow run summary:

``subdomains.txt``

``nmap_results.txt``

``nuclei_results.txt``

``arjun_results.json``

``all_params.txt``

🧠 Roadmap

[ ] Integrate HTTPx for live host verification and technology stack detection.

[ ] Add Screenshotting support for discovered subdomains.

[ ] Implement Slack/Telegram notification alternatives.

Disclaimer: This tool is intended for authorized security testing and educational purposes only. Always obtain permission before scanning any infrastructure.
