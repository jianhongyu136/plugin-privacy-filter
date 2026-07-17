module github.com/jhy/plugin-privacy-filter

go 1.26.0

require (
	github.com/router-for-me/CLIProxyAPI/v7 v7.0.0
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.47.0 // indirect

replace github.com/router-for-me/CLIProxyAPI/v7 => ../CLIProxyAPI
