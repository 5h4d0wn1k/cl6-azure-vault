# CL6 — Azure Key Vault Scanner

Enumerate Azure Key Vaults, inventory secrets/keys/certificates, and audit access policies.

## Overview

This project implements an Azure Key Vault security scanner that:
- Enumerates all Key Vaults in a subscription
- Inventories secrets, keys, and certificates with metadata
- Audits access policies for over-permissioned accounts
- Detects expired/expiring secrets and certificates
- Checks vault configuration (soft delete, purge protection, network ACLs)
- Analyzes key types and sizes for weak cryptography

## Features

- **Vault Enumeration**: Discover all Key Vaults in a subscription
- **Secret Inventory**: List secrets with expiry and staleness info
- **Certificate Analysis**: Detect expired/expiring certificates
- **Access Policy Audit**: Find over-permissioned identities and purge access
- **Key Analysis**: Check key types, sizes, and curves
- **Network ACL Check**: Verify network restrictions and Azure service bypass

## Usage

```bash
# Offline demo (no subscription, no token) — audit bundled fixtures
python3 azure_vault_scanner.py --demo

# Audit a custom Key Vault state fixtures file (offline)
python3 azure_vault_scanner.py --fixtures fixtures/vaults.json

# Offline audit with JSON report + CI exit code
python3 azure_vault_scanner.py --demo --output reports/cl6-report.json --exit-code-on-findings

# Live (authorized, your own subscription; credentials supplied at runtime only, never stored)
python3 azure_vault_scanner.py --subscription-id <SUB_ID> --token <BEARER_TOKEN>
```

## Requirements

- Python 3.7+ (standard library only)
- For **live** mode: Azure Bearer token with Key Vault read permissions. The token must be provided at runtime; it is never written to disk by this tool.

## Exit Codes

- `0` — completed cleanly (or demo finished without explicit CRITICAL/HIGH gate)
- `1` — error (missing fixtures, unreadable file, bad JSON)
- `2` — CRITICAL/HIGH findings present with `--exit-code-on-findings`

## Live Lab Test Plan

Runs entirely offline against `fixtures/vaults.json` — no Azure subscription, no token, no network.

1. **Demo**: `python3 azure_vault_scanner.py --demo` — expect CRITICAL/HIGH/MEDIUM/LOW findings for soft delete disabled, no purge protection, Standard SKU, open network ACL, AzureServices bypass, over-permissioned `/` purge access policies, expired certificates, expired/purgeable secrets, weak RSA key (1024-bit), and legacy P-256K curve. Exit `0`.
2. **JSON report**: `python3 azure_vault_scanner.py --demo --output reports/cl6-report.json` — verify report has `finding_count > 0`, `critical_high_count > 0`, and per-finding `severity`, `category`, `resource`, `message`, `remediation`.
3. **CI exit code**: `python3 azure_vault_scanner.py --demo --exit-code-on-findings; echo $?` — expect `2`.
4. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (exercises the offline auditor, access-policy auditor, and report serialisation).
5. **Live (optional)**: `--subscription-id` + `--token` at runtime for your own authorized subscription. Credentials are never stored.

## Metrics

- Detection rules exercised offline (real code paths): Soft Delete Disabled, No Purge Protection, Standard SKU, No Network Restrictions, Azure Services Bypass, access-policy over-permission/purge access (via `AccessPolicyAuditor`), Expired/Expiring Certificate, No Recovery Level, Disabled Certificate, Expired/Expiring/Purgeable/Disabled Secret, Weak Key Size, Legacy Curve, Disabled Key
- Offline auditor reuses the live `AccessPolicyAuditor` finding logic directly and mirrors the `KeyVaultEnumerator`/`CertificateAnalyzer`/`SecretInventory`/`KeyAnalyzer` detection semantics
- Every finding carries `severity`, `category`, `resource`, `message`, and a `remediation` string
- Exit-code contract: `0` clean / `1` error / `2` findings (with `--exit-code-on-findings`)
- Zero third-party dependencies; `--demo` requires no network or Azure access of any kind

## Legal Disclaimer

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the Azure subscription owner before using this tool
- Unauthorized access to Azure resources is illegal under federal and state laws
- This tool should ONLY be used on subscriptions you own or have written authorization to audit

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own Azure subscriptions
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Accessing Azure subscriptions without authorization
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
