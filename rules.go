package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

func validateCustomRules(customField []customFieldRule, customValue []customValueRule) error {
	for i, rule := range customField {
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("custom_field_rules[%d] requires a name", i)
		}
		if len(rule.Keys) == 0 {
			return fmt.Errorf("custom_field_rules[%d] requires at least one key", i)
		}
		for keyIndex, key := range rule.Keys {
			if strings.TrimSpace(key) == "" {
				return fmt.Errorf("custom_field_rules[%d].keys[%d] must not be empty", i, keyIndex)
			}
		}
		if rule.Regex != "" {
			if _, err := regexp.Compile(rule.Regex); err != nil {
				return fmt.Errorf("custom_field_rules[%d] has invalid regex", i)
			}
		}
	}
	for i, rule := range customValue {
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("custom_value_rules[%d] requires a name", i)
		}
		if rule.Regex == "" {
			return fmt.Errorf("custom_value_rules[%d] requires a regex", i)
		}
		if _, err := regexp.Compile(rule.Regex); err != nil {
			return fmt.Errorf("custom_value_rules[%d] has invalid regex", i)
		}
	}
	return nil
}

func validateBuiltinRuleNames(disabled, enabled []string) error {
	known := make(map[string]struct{}, len(builtinRules.FieldRules)+len(builtinRules.ValueRules))
	for _, rule := range builtinRules.FieldRules {
		known[strings.ToLower(rule.Name)] = struct{}{}
	}
	for _, rule := range builtinRules.ValueRules {
		known[strings.ToLower(rule.Name)] = struct{}{}
	}
	for listName, names := range map[string][]string{
		"disabled_builtin_rules": disabled,
		"enabled_builtin_rules":  enabled,
	} {
		for i, name := range names {
			if name != strings.TrimSpace(name) {
				return fmt.Errorf("%s[%d] must not contain surrounding whitespace", listName, i)
			}
			if _, ok := known[strings.ToLower(name)]; !ok {
				return fmt.Errorf("%s[%d] names an unknown builtin rule", listName, i)
			}
		}
	}
	return nil
}

// builtinRulesJSON holds the built-in rule definitions. It is embedded at build
// time so the plugin ships a single self-contained artifact.
//
//go:embed builtin_rules.json
var builtinRulesJSON []byte

// builtinValidators maps a value rule's "validate" name to its checksum
// function. Validators cannot be expressed in JSON, so the JSON references one
// by name and it is resolved here.
var builtinValidators = map[string]func(string) bool{
	"luhn":     validateLuhn,
	"china_id": validateChinaID,
}

// builtinFieldRuleDef is a field rule as declared in builtin_rules.json.
type builtinFieldRuleDef struct {
	Name             string   `json:"name"`
	Keys             []string `json:"keys"`
	EnabledByDefault bool     `json:"enabled_by_default"`
}

// builtinValueRuleDef is a value rule as declared in builtin_rules.json.
type builtinValueRuleDef struct {
	Name             string `json:"name"`
	Regex            string `json:"regex"`
	Validate         string `json:"validate"`
	EnabledByDefault bool   `json:"enabled_by_default"`
}

// builtinRulesDoc is the decoded shape of builtin_rules.json.
type builtinRulesDoc struct {
	FieldRules []builtinFieldRuleDef `json:"field_rules"`
	ValueRules []builtinValueRuleDef `json:"value_rules"`
}

// builtinRules is the parsed, compiled built-in rule set. It is parsed once at
// startup; a malformed embedded file is a build/packaging error and panics.
var builtinRules = mustLoadBuiltinRules()

func mustLoadBuiltinRules() builtinRulesDoc {
	var doc builtinRulesDoc
	if err := json.Unmarshal(builtinRulesJSON, &doc); err != nil {
		panic("privacy-filter: invalid embedded builtin_rules.json: " + err.Error())
	}
	return doc
}

// fieldRule matches JSON object keys by exact, case-insensitive name. A match
// replaces the whole value of that key. valueConstraint, when non-nil, limits
// redaction to values that match it.
type fieldRule struct {
	name             string
	keys             map[string]struct{}
	valueConstraint  *regexp.Regexp
	enabledByDefault bool
}

// valueRule matches sensitive substrings inside any string value. A match
// replaces only the matched fragment. validate, when non-nil, accepts a regex
// match only if it returns true (used for checksum-verified paterns).
type valueRule struct {
	name             string
	re               *regexp.Regexp
	validate         func(string) bool
	enabledByDefault bool
}

// ruleSet is the compiled, effective set of rules used by the scanner.
type ruleSet struct {
	fieldRules []fieldRule
	valueRules []valueRule
}

// customFieldRule is a user-defined field rule from configuration.
type customFieldRule struct {
	Name  string   `yaml:"name"`
	Keys  []string `yaml:"keys"`
	Regex string   `yaml:"regex"`
}

// customValueRule is a user-defined value rule from configuration.
type customValueRule struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

func lowerKeySet(keys []string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[strings.ToLower(k)] = struct{}{}
	}
	return set
}

func builtinFieldRules() []fieldRule {
	rules := make([]fieldRule, 0, len(builtinRules.FieldRules))
	for _, d := range builtinRules.FieldRules {
		rules = append(rules, fieldRule{
			name:             d.Name,
			keys:             lowerKeySet(d.Keys),
			enabledByDefault: d.EnabledByDefault,
		})
	}
	return rules
}

func builtinValueRules() []valueRule {
	rules := make([]valueRule, 0, len(builtinRules.ValueRules))
	for _, d := range builtinRules.ValueRules {
		var validate func(string) bool
		if d.Validate != "" {
			v, ok := builtinValidators[d.Validate]
			if !ok {
				panic("privacy-filter: unknown validator " + d.Validate + " for builtin rule " + d.Name)
			}
			validate = v
		}
		rules = append(rules, valueRule{
			name:             d.Name,
			re:               regexp.MustCompile(d.Regex),
			validate:         validate,
			enabledByDefault: d.EnabledByDefault,
		})
	}
	return rules
}

// compileRules builds the effective rule set from builtin rules (adjusted by the
// enable/disable lists) plus custom rules.
func compileRules(builtinEnabled bool, disabledNames, enabledNames []string, customField []customFieldRule, customValue []customValueRule) ruleSet {
	var rs ruleSet

	disabled := lowerKeySet(disabledNames)
	enabled := lowerKeySet(enabledNames)

	active := func(name string, def bool) bool {
		if !builtinEnabled {
			return false
		}
		lname := strings.ToLower(name)
		if _, ok := enabled[lname]; ok {
			return true
		}
		if _, ok := disabled[lname]; ok {
			return false
		}
		return def
	}

	for _, r := range builtinFieldRules() {
		if active(r.name, r.enabledByDefault) {
			rs.fieldRules = append(rs.fieldRules, r)
		}
	}
	for _, r := range builtinValueRules() {
		if active(r.name, r.enabledByDefault) {
			rs.valueRules = append(rs.valueRules, r)
		}
	}

	for _, c := range customField {
		if c.Name == "" || len(c.Keys) == 0 {
			continue
		}
		var vc *regexp.Regexp
		if c.Regex != "" {
			re, err := regexp.Compile(c.Regex)
			if err != nil {
				logrus.WithField("rule", c.Name).WithError(err).Warn("privacy-filter: skipping custom field rule with invalid regex")
				continue
			}
			vc = re
		}
		rs.fieldRules = append(rs.fieldRules, fieldRule{name: c.Name, keys: lowerKeySet(c.Keys), valueConstraint: vc, enabledByDefault: true})
	}

	for _, c := range customValue {
		if c.Name == "" || c.Regex == "" {
			continue
		}
		re, err := regexp.Compile(c.Regex)
		if err != nil {
			logrus.WithField("rule", c.Name).WithError(err).Warn("privacy-filter: skipping custom value rule with invalid regex")
			continue
		}
		rs.valueRules = append(rs.valueRules, valueRule{name: c.Name, re: re, enabledByDefault: true})
	}

	return rs
}

// validateLuhn reports whether s passes the Luhn checksum (digits only).
func validateLuhn(s string) bool {
	sum := 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validateChinaID reports whether s is a valid 18-digit China resident ID
// (ISO 7064 MOD 11-2 checksum).
func validateChinaID(s string) bool {
	if len(s) != 18 {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := []byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}
	sum := 0
	for i := 0; i < 17; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * weights[i]
	}
	got := s[17]
	if got == 'x' {
		got = 'X'
	}
	return got == checks[sum%11]
}
