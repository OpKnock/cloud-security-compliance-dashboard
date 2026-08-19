package compliance

import "testing"

func TestAWSScannerFindsPublicBucket(t *testing.T) {
	resource := map[string]any{"name": "prod-assets", "service": "s3", "public": true, "encrypted": false}
	findings := CheckResource(AWSScanner{}, resource)
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[0].ID != "AWS-S3-001" {
		t.Errorf("highest severity should sort first, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("public bucket should be critical, got %s", findings[0].Severity)
	}
}

func TestAWSScannerCleanResource(t *testing.T) {
	resource := map[string]any{"name": "backup-bucket", "service": "s3", "public": false, "encrypted": true}
	findings := CheckResource(AWSScanner{}, resource)
	if len(findings) != 0 {
		t.Fatalf("want no findings, got %+v", findings)
	}
}

func TestAzureAndGCPChecks(t *testing.T) {
	azure := CheckResource(AzureScanner{}, map[string]any{"name": "logs-storage", "service": "storage", "public": true})
	if len(azure) != 1 || azure[0].ID != "AZ-STG-001" {
		t.Fatalf("unexpected azure findings: %+v", azure)
	}
	gcp := CheckResource(GCPScanner{}, map[string]any{"name": "data-bucket", "service": "storage", "public": true})
	if len(gcp) != 1 || gcp[0].ID != "GCP-GCS-001" {
		t.Fatalf("unexpected gcp findings: %+v", gcp)
	}
}

func TestCheckResourceSortsBySeverity(t *testing.T) {
	resource := map[string]any{"name": "bad-sg", "service": "ec2", "open_inbound": true}
	findings := CheckResource(AWSScanner{}, resource)
	for i := 1; i < len(findings); i++ {
		if severityRank(findings[i-1].Severity) > severityRank(findings[i].Severity) {
			t.Fatalf("not sorted: %+v", findings)
		}
	}
}

func TestBuildReportScoring(t *testing.T) {
	resources := map[Provider][]map[string]any{
		ProviderAWS: {
			{"name": "prod-assets", "service": "s3", "public": true, "encrypted": false},
		},
	}
	report := BuildReport([]Scanner{AWSScanner{}}, resources)
	if report.Critical != 1 || report.Total != 2 {
		t.Fatalf("unexpected counts: critical=%d total=%d", report.Critical, report.Total)
	}
	if report.Overall > 100 || report.Overall < 0 {
		t.Fatalf("overall out of range: %f", report.Overall)
	}
	for _, s := range report.Scores {
		if s.Percent < 0 || s.Percent > 100 {
			t.Fatalf("score out of range: %+v", s)
		}
	}
}

func TestReportMarkdownSections(t *testing.T) {
	resources := map[Provider][]map[string]any{
		ProviderAWS: {{"name": "x", "public": true}},
	}
	report := BuildReport([]Scanner{AWSScanner{}}, resources)
	md := report.Markdown()
	for _, want := range []string{"# Cloud Compliance Dashboard", "## Findings", "AWS-S3-001", "Overall compliance"} {
		if !containsStr(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestFrameworksFor(t *testing.T) {
	if len(FrameworksFor(SeverityCritical)) != 4 {
		t.Error("critical should map to all frameworks")
	}
	if len(FrameworksFor(SeverityLow)) != 2 {
		t.Error("low should map to cis+soc2 only")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
