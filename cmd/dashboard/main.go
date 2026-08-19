package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"example.com/cloudcompliance/compliance"
)

func main() {
	output := flag.String("format", "markdown", "output format: markdown or json")
	flag.Parse()

	resources := map[compliance.Provider][]map[string]any{
		compliance.ProviderAWS: {
			{"name": "prod-assets", "service": "s3", "public": true, "encrypted": false},
			{"name": "backup-bucket", "service": "s3", "public": false, "encrypted": true},
			{"name": "app-role", "service": "iam", "wildcard": true},
			{"name": "web-sg", "service": "ec2", "open_inbound": true},
			{"name": "db-prod", "service": "rds", "public": true},
			{"name": "global-trail", "service": "cloudtrail", "enabled": true},
		},
		compliance.ProviderAzure: {
			{"name": "logs-storage", "service": "storage", "public": true},
			{"name": "rdp-nsg", "service": "network", "rdp_open": true},
			{"name": "vault-prod", "service": "keyvault", "firewall": true},
		},
		compliance.ProviderGCP: {
			{"name": "data-bucket", "service": "storage", "public": true},
			{"name": "main-sql", "service": "sql", "encrypted": false},
			{"name": "project-x", "service": "iam", "audit_logging": true},
		},
	}

	report := compliance.BuildReport(compliance.AllScanners, resources)
	switch *output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	default:
		fmt.Print(report.Markdown())
	}
}
