module main

go 1.23.0

replace github.com/inspektor-gadget/inspektor-gadget => ../../../../inspektor-gadget/

require github.com/inspektor-gadget/inspektor-gadget v0.0.0-00010101000000-000000000000

require (
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/tetratelabs/wazero v1.8.2 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v2 v2.4.0
)
