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
python3 azure_vault_scanner.py --subscription-id <SUB_ID> --token <BEARER_TOKEN>
```

## Requirements

- Python 3.7+ (standard library only)
- Azure Bearer token with Key Vault read permissions

## Legal Disclaimer

**IMPORTANT: Read before use.**

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
