package main

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

// The host preserves store metadata in the config_yaml passed to native plugins.
const hostStoreMetadataYAML = `store:
  schema-version: 2
  id: privacy-filter
  version: 0.0.0
  release-tag: v0.0.0
  repository: https://github.com/jianhongyu136/plugin-privacy-filter
  source-id: compatibility-fixture
  install:
    type: github-release
  future-host-field:
    token_label: NOT_A_PLUGIN_SETTING
`

func TestLifecycleAcceptsHostStoreMetadata(t *testing.T) {
	for _, method := range []string{pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure} {
		t.Run(method, func(t *testing.T) {
			reg := callRegister(t, method, "enabled: true\npriority: 7\nmode: filter\ntoken_label: COMPAT\n"+hostStoreMetadataYAML)
			if reg.SchemaVersion != pluginSchemaVersion || !reg.Capabilities.RequestInterceptor {
				t.Fatalf("host-managed plugin did not register its contract: %+v", reg)
			}
			if st := activeSnapshot(); st == nil || st.label != "COMPAT" || st.mode != modeFilter {
				t.Fatalf("host metadata changed the plugin settings: %+v", st)
			}
		})
	}
}

func TestLifecycleIgnoresUnusedHostAndPluginSettings(t *testing.T) {
	for _, unused := range []string{
		hostStoreMetadataYAML,
		"future_host_setting:\n  token_label: NOT_A_PLUGIN_SETTING\n",
		"removed_plugin_setting: true\n",
		"custom_value_rules:\n  - name: fixture\n    regex: FIXTURE\n    unused_rule_setting: true\n",
	} {
		for _, method := range []string{pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure} {
			callRegister(t, method, "mode: block\ntoken_label: ACTIVE\nvault_ttl_seconds: 60\n"+unused)
			st := activeSnapshot()
			if st == nil || st.label != "ACTIVE" || st.mode != modeBlock {
				t.Fatalf("unused fields changed known plugin settings: %+v", st)
			}
			if st.vault.ttl.Seconds() != 60 {
				t.Fatalf("known vault lifetime was not read: %s", st.vault.ttl)
			}
		}
	}
}

func TestHostStoreMetadataDoesNotBecomePluginConfigField(t *testing.T) {
	for _, field := range configFields() {
		if field.Name == "store" {
			t.Fatal("host-owned store metadata must not be exposed as a plugin setting")
		}
	}
}

func TestLifecycleAcceptsNullHostStoreMetadata(t *testing.T) {
	reg := callRegister(t, pluginabi.MethodPluginRegister, "store: null\n")
	if reg.SchemaVersion != pluginSchemaVersion {
		t.Fatalf("schema version = %d, want %d", reg.SchemaVersion, pluginSchemaVersion)
	}
}
