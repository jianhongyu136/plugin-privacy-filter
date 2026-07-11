package main

import (
	"encoding/json"
	"testing"
)

func hasFieldRule(rs ruleSet, name string) bool {
	for _, r := range rs.fieldRules {
		if r.name == name {
			return true
		}
	}
	return false
}

func hasValueRule(rs ruleSet, name string) bool {
	for _, r := range rs.valueRules {
		if r.name == name {
			return true
		}
	}
	return false
}

func TestBuiltinDefaultsOnOff(t *testing.T) {
	rs := compileRules(true, nil, nil, nil, nil)
	// Default-on field rules.
	for _, name := range []string{"password", "api_key", "secret", "token", "authorization", "private_key", "credential", "session"} {
		if !hasFieldRule(rs, name) {
			t.Errorf("expected default-on field rule %q", name)
		}
	}
	// Default-on value rules.
	for _, name := range []string{"openai_key", "anthropic_key", "aws_access_key", "google_api_key", "github_token", "slack_token", "bearer", "pem_block", "ssh_private_key"} {
		if !hasValueRule(rs, name) {
			t.Errorf("expected default-on value rule %q", name)
		}
	}
	// Default-off value rules.
	for _, name := range []string{"aws_secret_key", "jwt", "email", "phone_cn", "phone_e164", "id_card_cn", "credit_card", "ipv4"} {
		if hasValueRule(rs, name) {
			t.Errorf("expected default-off value rule %q to be absent", name)
		}
	}
}

func TestDisableBuiltinRule(t *testing.T) {
	rs := compileRules(true, []string{"password"}, nil, nil, nil)
	if hasFieldRule(rs, "password") {
		t.Error("password should be disabled")
	}
}

func TestEnableBuiltinRule(t *testing.T) {
	rs := compileRules(true, nil, []string{"jwt"}, nil, nil)
	if !hasValueRule(rs, "jwt") {
		t.Error("jwt should be enabled")
	}
}

func TestEnabledWinsOverDisabled(t *testing.T) {
	rs := compileRules(true, []string{"email"}, []string{"email"}, nil, nil)
	if !hasValueRule(rs, "email") {
		t.Error("email should be enabled (enable wins over disable)")
	}
}

func TestMasterSwitchOff(t *testing.T) {
	rs := compileRules(false, nil, []string{"jwt"}, nil, nil)
	if len(rs.fieldRules) != 0 || len(rs.valueRules) != 0 {
		t.Error("master switch off should disable all builtin rules")
	}
}

func TestCustomFieldRule(t *testing.T) {
	rs := compileRules(false, nil, nil, []customFieldRule{{Name: "custom1", Keys: []string{"x_secret"}}}, nil)
	if !hasFieldRule(rs, "custom1") {
		t.Error("custom field rule should be present")
	}
}

func TestCustomValueRule(t *testing.T) {
	rs := compileRules(false, nil, nil, nil, []customValueRule{{Name: "good", Regex: `foo[0-9]+`}})
	if !hasValueRule(rs, "good") {
		t.Error("valid custom value rule should be present")
	}
}

func TestValidateLuhn(t *testing.T) {
	if !validateLuhn("4242424242424242") {
		t.Error("known-good Luhn number should validate")
	}
	if validateLuhn("4242424242424241") {
		t.Error("bad Luhn number should fail")
	}
}

func TestValidateChinaID(t *testing.T) {
	if !validateChinaID("11010519491231002X") {
		t.Error("known-good China ID should validate")
	}
	if validateChinaID("110519491231021") {
		t.Error("wrong checksum should fail")
	}
}

func TestOpenSSHPrivateKeyUsesSpecificRule(t *testing.T) {
	rs := compileRules(true, nil, nil, nil, nil)
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	body, err := json.Marshal(map[string]any{"content": key})
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	result := scanJSONObjectForTest(t, body, rs, testTokenRe, testRedact)
	if len(result.Matches) != 1 {
		t.Fatalf("matches = %+v, want one OpenSSH private-key match", result.Matches)
	}
	if result.Matches[0].Rule != "ssh_private_key" {
		t.Fatalf("rule = %q, want ssh_private_key", result.Matches[0].Rule)
	}
}
