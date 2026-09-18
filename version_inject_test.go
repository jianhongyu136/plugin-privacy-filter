package main

import (
	"os"
	"testing"
)

func TestPluginVersionDefaultsToDev(t *testing.T) {
	if os.Getenv("PRIVACY_FILTER_EXPECT_VERSION") != "" {
		t.Skip("injected version binary is not asserting the default")
	}
	if pluginVersion != "dev" {
		t.Fatalf("pluginVersion = %q, want dev", pluginVersion)
	}
}
