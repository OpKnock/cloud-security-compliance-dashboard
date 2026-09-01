# Cloud Security Compliance Dashboard

A dashboard for monitoring and reporting cloud security compliance status across multiple providers and configurations.

## Overview

The Cloud Security Compliance Dashboard is an educational tool designed to demonstrate cloud security compliance monitoring and reporting techniques. This dashboard helps security professionals and DevOps teams understand how to track, monitor, and report on security compliance across multiple cloud providers in a controlled, educational environment.

**Important:** This tool is intended solely for educational and authorized cloud security monitoring purposes. Only monitor and assess cloud environments on accounts you own or have explicit written permission to test. Unauthorized monitoring of cloud resources may violate applicable terms of service and privacy regulations.

## Features

### Multi-Cloud Compliance Tracking

The dashboard provides unified visibility into security compliance across major cloud providers:

- **AWS**: Config rules, GuardDuty findings, Inspector scan results, IAM access analyzer
- **Azure**: Security center alerts, policy compliance, defender findings
- **GCP**: Security command center, cloud asset inventory, detection rules
- **Cross-cloud correlation**: Identify patterns and discrepancies across platforms

### Real-Time Violation Detection

- **Automated scanning**: Continuous or scheduled compliance checks
- **Violation classification**: Categorize findings by severity and type
- **Trend analysis**: Track violation patterns over time
- **Alert integration**: Connect with notification systems (Slack, email, PagerDuty)

### Automated Remediation Recommendations

- **Prescribed remediation steps** for common compliance violations
- **Priority scoring**: Based on impact and exploitability
- **Runbook integration**: Link to detailed remediation guides
- **One-click remediation** for supported actions (where API allows)

### Compliance Report Generation

- **Customizable report templates** for different stakeholders
- **Executive summaries** with key metrics and trends
- **Technical details** for auditors and security teams
- **Export formats**: JSON, CSV, PDF, HTML

### Integration Ecosystem

- **API-first design**: Programmatic access for CI/CD integration
- **Webhook support**: Notify external systems of compliance changes
- **Terraform provider**: Generate compliance-as-code configurations
- **Dashboard customization**: Tailor views and metrics to organizational needs

## Installation

### Requirements

- **Go 1.21+**: Go programming language runtime
- **Optional**: Access to cloud provider APIs (for full functionality)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/OpKnock/cloud-security-compliance-dashboard.git

# Build the dashboard command
go install github.com/OpKnock/cloud-security-dashboard/cmd/dashboard@latest
```

### Verify Installation

```bash
dashboard --help
```

## Usage

### Start the Dashboard Server

```bash
# Using the installed binary
dashboard

# Or run directly
go run ./cmd/dashboard.go
```

### Check Compliance Status

```bash
# Check compliance for specific cloud
dashboard check --cloud aws
dashboard check --cloud azure
dashboard check --cloud gcp

# Or check all configured clouds
dashboard check --all
```

### Generate Reports

```bash
# Generate a compliance report
dashboard report --output compliance-report.json

# Generate an executive summary
dashboard report --format executive --output exec-summary.pdf
```

### Programmatic Use

```go
import "github.com/OpKnock/cloud-security-dashboard"

// Initialize the dashboard
dash := dashboard.New()

// Check AWS compliance
awsResults := dash.CheckAWS(ctx, awsConfig)

// Generate a report
report := dash.GenerateReport(ctx, dashboard.ReportOptions{
    Format: "json",
    Output: "compliance-report.json",
})
```

## Legal and Ethical Notes

### Authorized Monitoring Only

This tool is designed for authorized cloud security monitoring. Key principles:

- **Only monitor cloud accounts you own or administer**
- **Obtain explicit written permission** before assessing any cloud environment
- **Report any compliance issues** to the appropriate cloud service provider
- **Never monitor cloud resources** on accounts you do not have explicit authorization for

### Legal Compliance

- Unauthorized cloud monitoring may violate terms of service of cloud providers
- Privacy laws (GDPR, CCPA, etc.) may apply depending on data accessed
- Always obtain explicit written permission before testing any cloud environment

### Educational Value

Understanding cloud compliance monitoring helps security teams:

- Implement proper cloud security controls
- Design effective compliance monitoring programs
- Respond to compliance violations systematically
- Build multi-cloud security postures

## License

MIT - This project is free to use, modify, and distribute for educational purposes. See the LICENSE file for full terms and conditions.