// config.go
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

// pluginConfig is the typed view of the plugins.configs.privacy-filter YAML subtree.
type pluginConfig struct {
	Enabled              bool              `yaml:"enabled"`
	Priority             int               `yaml:"priority"`
	Mode                 string            `yaml:"mode"`
	BlockReturnOriginal  bool              `yaml:"block_return_original"`
	TokenLabel           string            `yaml:"token_label"`
	VaultTTLSeconds      int               `yaml:"vault_ttl_seconds"`
	VaultMaxEntries      int               `yaml:"vault_max_entries"`
	BuiltinRulesEnabled  bool              `yaml:"builtin_rules_enabled"`
	DisabledBuiltinRules []string          `yaml:"disabled_builtin_rules"`
	EnabledBuiltinRules  []string          `yaml:"enabled_builtin_rules"`
	CustomFieldRules     []customFieldRule `yaml:"custom_field_rules"`
	CustomValueRules     []customValueRule `yaml:"custom_value_rules"`
}

// lifecycleRequestPayload mirrors the host rpcLifecycleRequest JSON delivered on
// plugin.register / plugin.reconfigure. config_yaml is raw YAML text.
type lifecycleRequestPayload struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

// Schema 4 provides the stateful stream session lifecycle required by this plugin.
const pluginSchemaVersion uint32 = pluginabi.SchemaVersionStatefulStreamInterceptor

type unsupportedSchemaVersionError struct {
	received uint32
}

func (e *unsupportedSchemaVersionError) Error() string {
	return fmt.Sprintf(
		"unsupported schema version %d; minimum supported version is %d",
		e.received,
		pluginSchemaVersion,
	)
}

// runtimeState is the immutable set of runtime values that must change together
// on (re)configure: the compiled rules, the token label, the compiled token
// pattern for that label, the all-label restoration pattern, and the vault that
// holds token->secret mappings. Publishing them as one atomic snapshot ensures
// a request never observes a mismatched rules/label/vault pairing. Patterns are
// compiled once on reconfigure rather than on request and response hot paths.
type runtimeState struct {
	rules               ruleSet
	mode                string
	blockReturnOriginal bool
	label               string
	tokenRe             *regexp.Regexp
	restoreTokenRe      *regexp.Regexp
	vault               *vault
}

// activeState holds the current *runtimeState. It is swapped atomically so
// readers always see a self-consistent rules/label/vault triple.
var activeState atomic.Pointer[runtimeState]

var tokenLabelPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

const (
	modeFilter = "filter"
	modeBlock  = "block"
)

// defaultConfig returns a config populated with the documented defaults.
func defaultConfig() pluginConfig {
	return pluginConfig{
		Mode:                modeFilter,
		BlockReturnOriginal: false,
		TokenLabel:          "REDACTED",
		VaultTTLSeconds:     3600,
		VaultMaxEntries:     1000,
		BuiltinRulesEnabled: true,
	}
}

// parseLifecycleConfig extracts config_yaml from the RPC request and unmarshals
// it over a default-seeded config so omitted keys keep their defaults.
func parseLifecycleConfig(request []byte) (pluginConfig, error) {
	var payload lifecycleRequestPayload
	if err := json.Unmarshal(request, &payload); err != nil {
		return pluginConfig{}, err
	}
	if payload.SchemaVersion < pluginSchemaVersion {
		return pluginConfig{}, &unsupportedSchemaVersionError{received: payload.SchemaVersion}
	}
	cfg := defaultConfig()
	if len(payload.ConfigYAML) > 0 {
		decoder := yaml.NewDecoder(bytes.NewReader(payload.ConfigYAML))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			return pluginConfig{}, err
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			if err == nil {
				return pluginConfig{}, errors.New("config_yaml must contain exactly one YAML document")
			}
			return pluginConfig{}, err
		}
	}
	return cfg, nil
}

// applyConfig validates and compiles the configuration, reconfigures the shared
// vault in place, then publishes rules, label, patterns, and vault as one atomic
// snapshot. Reusing the vault preserves in-flight mappings and late writes from
// handlers that still hold an older runtime snapshot.
func applyConfig(cfg pluginConfig) error {
	if cfg.Mode != modeFilter && cfg.Mode != modeBlock {
		return errors.New("mode must be filter or block")
	}
	if !tokenLabelPattern.MatchString(cfg.TokenLabel) {
		return errors.New("token_label must match [A-Za-z][A-Za-z0-9_-]{0,63}")
	}
	if cfg.VaultTTLSeconds <= 0 {
		return errors.New("vault_ttl_seconds must be positive")
	}
	const maxVaultTTLSeconds = int64(^uint64(0)>>1) / int64(time.Second)
	if int64(cfg.VaultTTLSeconds) > maxVaultTTLSeconds {
		return errors.New("vault_ttl_seconds exceeds duration limit")
	}
	if cfg.VaultMaxEntries <= 0 {
		return errors.New("vault_max_entries must be positive")
	}
	if err := validateCustomRules(cfg.CustomFieldRules, cfg.CustomValueRules); err != nil {
		return err
	}
	if err := validateBuiltinRuleNames(cfg.DisabledBuiltinRules, cfg.EnabledBuiltinRules); err != nil {
		return err
	}

	rules := compileRules(
		cfg.BuiltinRulesEnabled,
		cfg.DisabledBuiltinRules,
		cfg.EnabledBuiltinRules,
		cfg.CustomFieldRules,
		cfg.CustomValueRules,
	)
	ttl := time.Duration(cfg.VaultTTLSeconds) * time.Second
	var v *vault
	if prev := activeState.Load(); prev != nil && prev.vault != nil {
		v = prev.vault
		v.reconfigure(cfg.VaultMaxEntries, ttl)
	} else {
		v = newVault(cfg.VaultMaxEntries, ttl)
	}
	v.startCleanup()
	streamCarry.startCleanup()

	activeState.Store(&runtimeState{
		rules:               rules,
		mode:                cfg.Mode,
		blockReturnOriginal: cfg.BlockReturnOriginal,
		label:               cfg.TokenLabel,
		tokenRe:             tokenPattern(cfg.TokenLabel),
		restoreTokenRe:      restoreTokenPattern(),
		vault:               v,
	})
	return nil
}

// activeSnapshot returns the current runtime state as a single consistent
// snapshot, or nil if configuration has not been applied yet. Callers on a
// request path must read the snapshot once and use its rules, label, and vault
// together so a concurrent reconfigure cannot split the triple.
func activeSnapshot() *runtimeState {
	return activeState.Load()
}

// activeRuleSet returns the compiled rule set and token label currently in use.
func activeRuleSet() (ruleSet, string) {
	if st := activeState.Load(); st != nil {
		return st.rules, st.label
	}
	return ruleSet{}, ""
}

// configFields declares the schema for the admin panel form.
func configFields() []pluginapi.ConfigField {
	return []pluginapi.ConfigField{
		{Name: "mode", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{modeFilter, modeBlock}, Description: "Request handling mode: filter replaces privacy values; block rejects with redacted context unless block_return_original is enabled."},
		{Name: "block_return_original", Type: pluginapi.ConfigFieldTypeBoolean, Description: "In block mode, include the matched original value in the rejection reason, bounded to 160 Unicode characters."},
		{Name: "token_label", Type: pluginapi.ConfigFieldTypeString, Description: "Label inside <LABEL_hash>; must match [A-Za-z][A-Za-z0-9_-]{0,63}."},
		{Name: "vault_ttl_seconds", Type: pluginapi.ConfigFieldTypeInteger, Description: "How long a token->value mapping is retained for restore."},
		{Name: "vault_max_entries", Type: pluginapi.ConfigFieldTypeInteger, Description: "Maximum number of token->value mappings kept in memory."},
		{Name: "builtin_rules_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Master switch for all builtin detection rules."},
		{Name: "disabled_builtin_rules", Type: pluginapi.ConfigFieldTypeArray, Description: "Builtin rule names to turn off (default-on rules)."},
		{Name: "enabled_builtin_rules", Type: pluginapi.ConfigFieldTypeArray, Description: "Builtin rule names to turn on (default-off rules); wins over disabled."},
		{Name: "custom_field_rules", Type: pluginapi.ConfigFieldTypeArray, Description: "Custom field-name rules: objects of {name, keys[], regex?}."},
		{Name: "custom_value_rules", Type: pluginapi.ConfigFieldTypeArray, Description: "Custom value-pattern rules: objects of {name, regex}."},
	}
}
