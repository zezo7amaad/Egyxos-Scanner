# 🛡️ Egyxos Scanner
**Automated Reconnaissance & Vulnerability Monitor**

Egyxos Scanner is a cloud-native security tool designed to monitor attack surfaces. It automates subdomain discovery and vulnerability scanning using industry-standard tools.

## 🚀 Features
* **Continuous Monitoring:** Runs every 6 hours via GitHub Actions.
* **Smart Comparison:** Only alerts you when *new* subdomains are found.
* **Instant Alerts:** Integrated with Discord Webhooks for real-time SOC notifications.
* **Toolchain:** Utilizes Subfinder, Nuclei, and custom Python logic.

## 🛠️ Architecture
1. **GitHub Actions:** Orchestrates the scanning environment.
2. **Subfinder:** Performs passive/active subdomain enumeration.
3. **Python (egyxos_logic):** Handles data comparison and Discord API integration.
