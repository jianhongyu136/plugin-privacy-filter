// config_test.go
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func lifecycleRequest(t *testing.T, yamlText string) []byte {
	return lifecycleRequestForSchema(t, yamlText, pluginSchemaVersion)
}

func lifecycleRequestForSchema(t *testing.T, yamlText string, schemaVersion uint32) []byte {
	t.Helper()
	payload := struct {
		ConfigYAML    []byte `json:"config_yaml"`
		SchemaVersion uint32 `json:"schema_version"`
	}{ConfigYAML: []byte(yamlText), SchemaVersion: schemaVersion}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal lifecycle request: %v", err)
	}
	return raw
}

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Mode != modeFilter {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, modeFilter)
	}
	if cfg.BlockReturnOriginal {
		t.Fatal("BlockReturnOriginal = true, want false")
	}
	if cfg.TokenLabel != "REDACTED" {
		t.Fatalf("TokenLabel = %q, want REDACTED", cfg.TokenLabel)
	}
	if cfg.VaultTTLSeconds != 3600 {
		t.Fatalf("VaultTTLSeconds = %d, want 3600", cfg.VaultTTLSeconds)
	}
	if cfg.VaultMaxEntries != 1000 {
		t.Fatalf("VaultMaxEntries = %d, want 1000", cfg.VaultMaxEntries)
	}
	if !cfg.BuiltinRulesEnabled {
		t.Fatalf("BuiltinRulesEnabled = false, want true")
	}
}

func TestParseLifecycleConfigOverrides(t *testing.T) {
	yamlText := "enabled: true\npriority: 100\nmode: block\nblock_return_original: true\ntoken_label: MASKED\nvault_ttl_seconds: 60\nvault_max_entries: 5\nbuiltin_rules_enabled: false\n"
	cfg, err := parseLifecycleConfig(lifecycleRequest(t, yamlText))
	if err != nil {
		t.Fatalf("parseLifecycleConfig: %v", err)
	}
	if cfg.TokenLabel != "MASKED" {
		t.Fatalf("TokenLabel = %q, want MASKED", cfg.TokenLabel)
	}
	if cfg.Mode != modeBlock {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, modeBlock)
	}
	if !cfg.BlockReturnOriginal {
		t.Fatalf("BlockReturnOriginal = false, want true")
	}
	if cfg.VaultTTLSeconds != 60 {
		t.Fatalf("VaultTTLSeconds = %d, want 60", cfg.VaultTTLSeconds)
	}
	if cfg.VaultMaxEntries != 5 {
		t.Fatalf("VaultMaxEntries = %d, want 5", cfg.VaultMaxEntries)
	}
	if cfg.BuiltinRulesEnabled {
		t.Fatalf("BuiltinRulesEnabled = true, want false")
	}
}

func TestParseLifecycleConfigDefaultsWhenEmpty(t *testing.T) {
	cfg, err := parseLifecycleConfig(lifecycleRequest(t, "enabled: false\npriority: 0\n"))
	if err != nil {
		t.Fatalf("parseLifecycleConfig: %v", err)
	}
	if cfg.TokenLabel != "REDACTED" {
		t.Fatalf("TokenLabel = %q, want REDACTED (default)", cfg.TokenLabel)
	}
	if cfg.VaultTTLSeconds != 3600 {
		t.Fatalf("VaultTTLSeconds = %d, want 3600 (default)", cfg.VaultTTLSeconds)
	}
}

func TestExplicitEmptyTokenLabelIsNotDefaulted(t *testing.T) {
	cfg, err := parseLifecycleConfig(lifecycleRequest(t, `token_label: ""`))
	if err != nil {
		t.Fatalf("parseLifecycleConfig: %v", err)
	}
	if cfg.TokenLabel != "" {
		t.Fatalf("explicit empty token label was normalized to %q", cfg.TokenLabel)
	}
}

func TestLifecycleConfigRejectsUnknownFieldsAndExtraDocuments(t *testing.T) {
	for _, yamlText := range []string{
		"vault_ttl_second: 60\n",
		"custom_value_rules:\n  - name: marker\n    regex: ok\n    future: true\n",
		"mode: filter\n---\nmode: block\n",
	} {
		if _, err := parseLifecycleConfig(lifecycleRequest(t, yamlText)); err == nil {
			t.Fatalf("invalid YAML configuration was accepted: %q", yamlText)
		}
	}
}

func TestApplyConfigBuildsRuntimeState(t *testing.T) {
	cfg := defaultConfig()
	cfg.CustomValueRules = []customValueRule{{Name: "test_pat", Regex: "TESTSECRET[0-9]+"}}
	if err := applyConfig(cfg); err != nil {
		t.Fatalf("applyConfig: %v", err)
	}

	rules, label := activeRuleSet()
	if label != "REDACTED" {
		t.Fatalf("active label = %q, want REDACTED", label)
	}
	found := false
	for _, r := range rules.valueRules {
		if r.name == "test_pat" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("custom value rule test_pat not present in active rule set")
	}
	if getSharedVault() == nil {
		t.Fatalf("applyConfig did not set the shared vault")
	}
}

func TestInvalidConfigStructureRejectsAndPreservesSnapshot(t *testing.T) {
	stable := defaultConfig()
	stable.TokenLabel = "STABLE"
	stable.VaultMaxEntries = 3
	if err := applyConfig(stable); err != nil {
		t.Fatalf("apply stable config: %v", err)
	}
	before := activeSnapshot()
	token := makeToken("STABLE", "in-flight")
	before.vault.Put(token, "in-flight")

	tests := []struct {
		name   string
		mutate func(*pluginConfig)
	}{
		{name: "zero ttl", mutate: func(cfg *pluginConfig) { cfg.VaultTTLSeconds = 0 }},
		{name: "negative capacity", mutate: func(cfg *pluginConfig) { cfg.VaultMaxEntries = -1 }},
		{name: "ttl duration overflow", mutate: func(cfg *pluginConfig) { cfg.VaultTTLSeconds = int(int64(^uint64(0)>>1)/int64(time.Second) + 1) }},
		{name: "field missing name", mutate: func(cfg *pluginConfig) { cfg.CustomFieldRules = []customFieldRule{{Keys: []string{"password"}}} }},
		{name: "field missing keys", mutate: func(cfg *pluginConfig) { cfg.CustomFieldRules = []customFieldRule{{Name: "password"}} }},
		{name: "field empty key", mutate: func(cfg *pluginConfig) {
			cfg.CustomFieldRules = []customFieldRule{{Name: "password", Keys: []string{""}}}
		}},
		{name: "value missing name", mutate: func(cfg *pluginConfig) { cfg.CustomValueRules = []customValueRule{{Regex: "secret"}} }},
		{name: "value missing regex", mutate: func(cfg *pluginConfig) { cfg.CustomValueRules = []customValueRule{{Name: "marker"}} }},
		{name: "unknown disabled builtin", mutate: func(cfg *pluginConfig) { cfg.DisabledBuiltinRules = []string{"not-a-rule"} }},
		{name: "unknown enabled builtin", mutate: func(cfg *pluginConfig) { cfg.EnabledBuiltinRules = []string{"not-a-rule"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.TokenLabel = "SHOULD_NOT_PUBLISH"
			cfg.VaultMaxEntries = 1
			tt.mutate(&cfg)
			if err := applyConfig(cfg); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
			if activeSnapshot() != before {
				t.Fatal("invalid configuration replaced the active snapshot")
			}
			if got, ok := before.vault.Get(token); !ok || got != "in-flight" {
				t.Fatalf("invalid configuration disturbed mapping: got=%q ok=%v", got, ok)
			}
		})
	}
}

func TestBuiltinRuleNamesRejectSurroundingWhitespace(t *testing.T) {
	cfg := defaultConfig()
	cfg.EnabledBuiltinRules = []string{" email "}
	if err := applyConfig(cfg); err == nil {
		t.Fatal("builtin rule name with surrounding whitespace was accepted")
	}
}

func TestInvalidModeRejectsAndPreservesSnapshot(t *testing.T) {
	cfg := defaultConfig()
	cfg.TokenLabel = "STABLE"
	cfg.VaultMaxEntries = 3
	if err := applyConfig(cfg); err != nil {
		t.Fatalf("apply stable config: %v", err)
	}
	before := activeSnapshot()
	token := makeToken("STABLE", "in-flight")
	before.vault.Put(token, "in-flight")

	for _, invalidMode := range []string{"", "BLOCK", "reject"} {
		invalid := defaultConfig()
		invalid.Mode = invalidMode
		invalid.TokenLabel = "SHOULD_NOT_PUBLISH"
		invalid.VaultMaxEntries = 1
		if err := applyConfig(invalid); err == nil {
			t.Fatalf("invalid mode %q accepted", invalidMode)
		}
		if got := activeSnapshot(); got != before {
			t.Fatalf("invalid mode %q replaced active snapshot", invalidMode)
		}
		if got, ok := before.vault.Get(token); !ok || got != "in-flight" {
			t.Fatalf("invalid mode %q disturbed in-flight mapping: got=%q ok=%v", invalidMode, got, ok)
		}
	}
}

func TestInvalidTokenLabelRejectsAndPreservesSnapshot(t *testing.T) {
	cfg := defaultConfig()
	cfg.TokenLabel = "STABLE"
	cfg.VaultMaxEntries = 3
	cfg.VaultTTLSeconds = 60
	if err := applyConfig(cfg); err != nil {
		t.Fatalf("apply stable config: %v", err)
	}
	before := activeSnapshot()
	token := makeToken("STABLE", "in-flight")
	before.vault.Put(token, "in-flight")

	invalid := defaultConfig()
	invalid.TokenLabel = "A>B"
	invalid.VaultMaxEntries = 1
	invalid.VaultTTLSeconds = 1
	if err := applyConfig(invalid); err == nil {
		t.Fatal("invalid token label must reject configuration")
	}
	if got := activeSnapshot(); got != before {
		t.Fatal("invalid token label replaced the active snapshot")
	}
	before.vault.mu.Lock()
	maxEntries, ttl := before.vault.maxEntries, before.vault.ttl
	before.vault.mu.Unlock()
	if maxEntries != 3 || ttl != time.Minute {
		t.Fatalf("invalid label changed vault settings: max=%d ttl=%s", maxEntries, ttl)
	}
	if got, ok := before.vault.Get(token); !ok || got != "in-flight" {
		t.Fatalf("invalid label disturbed in-flight mapping: got=%q ok=%v", got, ok)
	}
}

func TestTokenLabelGrammar(t *testing.T) {
	valid := []string{"A", "REDACTED", "A_b-9", strings.Repeat("A", 64)}
	for _, label := range valid {
		cfg := defaultConfig()
		cfg.TokenLabel = label
		if err := applyConfig(cfg); err != nil {
			t.Fatalf("valid label %q rejected: %v", label, err)
		}
	}
	invalid := []string{"_BAD", "9BAD", "A B", "A\nB", strings.Repeat("A", 65)}
	for _, label := range invalid {
		cfg := defaultConfig()
		cfg.TokenLabel = label
		if err := applyConfig(cfg); err == nil {
			t.Fatalf("invalid label %q accepted", label)
		}
	}
}

func TestConfigFieldsDeclaresSchema(t *testing.T) {
	fields := configFields()
	want := map[string]bool{
		"mode":                   false,
		"block_return_original":  false,
		"token_label":            false,
		"vault_ttl_seconds":      false,
		"vault_max_entries":      false,
		"builtin_rules_enabled":  false,
		"disabled_builtin_rules": false,
		"enabled_builtin_rules":  false,
		"custom_field_rules":     false,
		"custom_value_rules":     false,
	}
	for _, f := range fields {
		if f.Name == "mode" {
			if f.Type != pluginapi.ConfigFieldTypeEnum {
				t.Fatalf("mode field type = %q, want %q", f.Type, pluginapi.ConfigFieldTypeEnum)
			}
			if len(f.EnumValues) != 2 || f.EnumValues[0] != modeFilter || f.EnumValues[1] != modeBlock {
				t.Fatalf("mode enum values = %#v, want %#v", f.EnumValues, []string{modeFilter, modeBlock})
			}
		}
		if f.Name == "block_return_original" && f.Type != pluginapi.ConfigFieldTypeBoolean {
			t.Fatalf("block_return_original field type = %q, want %q", f.Type, pluginapi.ConfigFieldTypeBoolean)
		}
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("config field %q not declared", name)
		}
	}
}
