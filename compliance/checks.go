package compliance

type AWSScanner struct{}

func (AWSScanner) Provider() Provider { return ProviderAWS }

func (AWSScanner) Checks() []Check {
	return []Check{
		{
			ID:          "AWS-S3-001",
			Service:     "s3",
			Description: "S3 bucket publicly readable",
			Severity:    SeverityCritical,
			CISControl:  "2.1.1",
			Frameworks:  []string{"cis", "soc2", "hipaa", "pci-dss"},
			Remediation: "s3_public_block = { block_public_acls = true }",
			Pass:        func(r map[string]any) bool { return !normalize(r["public"]) },
		},
		{
			ID:          "AWS-S3-002",
			Service:     "s3",
			Description: "S3 bucket encryption disabled",
			Severity:    SeverityHigh,
			CISControl:  "2.1.5",
			Frameworks:  []string{"cis", "hipaa"},
			Remediation: "aws s3api put-bucket-encryption --bucket ${name} --server-side-encryption-configuration ...",
			Pass:        func(r map[string]any) bool { return normalize(r["encrypted"]) },
		},
		{
			ID:          "AWS-IAM-001",
			Service:     "iam",
			Description: "IAM role allows wildcard actions",
			Severity:    SeverityHigh,
			CISControl:  "1.4",
			Frameworks:  []string{"cis", "soc2", "pci-dss"},
			Remediation: "Remove \"*:*\" statements; scope actions to least privilege.",
			Pass:        func(r map[string]any) bool { return !normalize(r["wildcard"]) },
		},
		{
			ID:          "AWS-EC2-001",
			Service:     "ec2",
			Description: "Security group allows unrestricted inbound from 0.0.0.0/0",
			Severity:    SeverityCritical,
			CISControl:  "4.1",
			Frameworks:  []string{"cis", "soc2", "hipaa", "pci-dss"},
			Remediation: "Remove 0.0.0.0/0 ingress rules or restrict to known CIDRs.",
			Pass:        func(r map[string]any) bool { return !normalize(r["open_inbound"]) },
		},
		{
			ID:          "AWS-RDS-001",
			Service:     "rds",
			Description: "RDS instance publicly accessible",
			Severity:    SeverityHigh,
			CISControl:  "2.5.1",
			Frameworks:  []string{"cis", "soc2", "hipaa", "pci-dss"},
			Remediation: "Set PubliclyAccessible=false on the RDS instance.",
			Pass:        func(r map[string]any) bool { return !normalize(r["public"]) },
		},
		{
			ID:          "AWS-CLOUDTRAIL-001",
			Service:     "cloudtrail",
			Description: "CloudTrail not enabled in region",
			Severity:    SeverityMedium,
			CISControl:  "3.1",
			Frameworks:  []string{"cis", "soc2"},
			Remediation: "Create a CloudTrail trail with multi-region logging.",
			Pass:        func(r map[string]any) bool { return normalize(r["enabled"]) },
		},
	}
}

type AzureScanner struct{}

func (AzureScanner) Provider() Provider { return ProviderAzure }

func (AzureScanner) Checks() []Check {
	return []Check{
		{
			ID:          "AZ-STG-001",
			Service:     "storage",
			Description: "Storage account allows public blob access",
			Severity:    SeverityHigh,
			CISControl:  "3.7",
			Frameworks:  []string{"cis", "soc2"},
			Remediation: "az storage account update --name ${name} --allow-blob-public-access false",
			Pass:        func(r map[string]any) bool { return !normalize(r["public"]) },
		},
		{
			ID:          "AZ-NSG-001",
			Service:     "network",
			Description: "Network security group permits port 3389 to the internet",
			Severity:    SeverityHigh,
			CISControl:  "6.1",
			Frameworks:  []string{"cis", "pci-dss"},
			Remediation: "Remove the 0.0.0.0/0 RDP rule from the NSG.",
			Pass:        func(r map[string]any) bool { return !normalize(r["rdp_open"]) },
		},
		{
			ID:          "AZ-KV-001",
			Service:     "keyvault",
			Description: "Key Vault firewall not enabled",
			Severity:    SeverityMedium,
			CISControl:  "8.5",
			Frameworks:  []string{"cis", "hipaa"},
			Remediation: "Enable Key Vault firewall and restrict allowed networks.",
			Pass:        func(r map[string]any) bool { return normalize(r["firewall"]) },
		},
	}
}

type GCPScanner struct{}

func (GCPScanner) Provider() Provider { return ProviderGCP }

func (GCPScanner) Checks() []Check {
	return []Check{
		{
			ID:          "GCP-GCS-001",
			Service:     "storage",
			Description: "Cloud Storage bucket has public IAM binding",
			Severity:    SeverityHigh,
			CISControl:  "5.1",
			Frameworks:  []string{"cis", "soc2"},
			Remediation: "gcloud storage buckets update gs://${name} --no-public-access-prevention",
			Pass:        func(r map[string]any) bool { return !normalize(r["public"]) },
		},
		{
			ID:          "GCP-SQL-001",
			Service:     "sql",
			Description: "Cloud SQL instance encryption not enforced",
			Severity:    SeverityHigh,
			CISControl:  "6.1",
			Frameworks:  []string{"cis", "hipaa"},
			Remediation: "Enable CMEK/disk encryption for the SQL instance.",
			Pass:        func(r map[string]any) bool { return normalize(r["encrypted"]) },
		},
		{
			ID:          "GCP-AUDIT-001",
			Service:     "iam",
			Description: "Audit logging not configured",
			Severity:    SeverityMedium,
			CISControl:  "2.1",
			Frameworks:  []string{"cis", "soc2"},
			Remediation: "gcloud projects add-iam-policy-binding ${name} --role=roles/logging.logWriter",
			Pass:        func(r map[string]any) bool { return normalize(r["audit_logging"]) },
		},
	}
}

var AllScanners = []Scanner{AWSScanner{}, AzureScanner{}, GCPScanner{}}
