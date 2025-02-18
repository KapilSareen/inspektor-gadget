package inspect

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	// "github.com/cilium/ebpf"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v2"

	"github.com/tetratelabs/wazero"
)

type Config struct {
	Name             string                      `yaml:"name"`
	Description      string                      `yaml:"description"`
	HomepageURL      string                      `yaml:"homepageURL"`
	DocumentationURL string                      `yaml:"documentationURL"`
	SourceURL        string                      `yaml:"sourceURL"`
	Datasources      map[string]Datasource       `yaml:"datasources"`
	Params           map[string]map[string]Param `yaml:"params"`
}

type Datasource struct {
	Fields map[string]Field `yaml:"fields"`
}

type Field struct {
	Annotations map[string]interface{} `yaml:"annotations"`
}

type Param struct {
	Key          string `yaml:"key"`
	DefaultValue string `yaml:"defaultValue"`
	Description  string `yaml:"description"`
}

// GadgetImageDesc is the metadata that will be built from the image.
type GadgetImageDescEbpf struct {
	Sections []string
	Maps     []MapDesc
	Programs []ProgramDesc
}

// MapDesc holds basic information about an eBPF map.
type MapDesc struct {
	Name string
	Type string
}

// ProgramDesc holds information about an eBPF program.
type ProgramDesc struct {
	Section  string
	Bytecode []byte
	Source   string // if available
}

type WasmData struct {
	GadgetAPIVersion string   `column:"gadgetAPIVersion"`
	Upcalls          []string `column:"upcalls"`
}

type Annotations struct {
	Description          string `yaml:"description,omitempty"`
	Template             string `yaml:"template,omitempty"`
	ColumnsWidth         int    `yaml:"columns.width,omitempty"`
	ColumnsHidden        string `yaml:"columns.hidden,omitempty"`
	ColumnsAlignment     string `yaml:"columns.alignment,omitempty"`
	JSONSkip             string `yaml:"json.skip,omitempty"`
	UIDGIDResolverTarget string `yaml:"uidgidresolver.target,omitempty"`
}

func GetBlobFromLayer(storePath string, digest ocispec.Descriptor) ([]byte, error) {
	// getBlobFromLayer returns the blob from the layer.
	pathToBlob := path.Join(storePath, "blobs", "sha256", strings.Split(digest.Digest.String(), ":")[1])
	blob, err := os.ReadFile(pathToBlob)
	if err != nil {
		return nil, fmt.Errorf("reading blob: %w", err)
	}
	return blob, nil
}

// LoadEbpfModule loads the eBPF module.

	// with debug/elf
func LoadEbpfModule(ebpfBlob []byte) ([]string, []MapDesc, []ProgramDesc, error) {
	sections := []string{}
	maps := []MapDesc{}
	programs := []ProgramDesc{}
	ef, err := elf.NewFile(bytes.NewReader(ebpfBlob))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse ELF: %w", err)
	}

	for _, sec := range ef.Sections {
		sections = append(sections, sec.Name)
	}

	var mapsSec *elf.Section
	mapsSecIndex := -1

	for i, sec := range ef.Sections {
		if sec.Name == ".maps" {
			mapsSec = sec
			mapsSecIndex = i
			break
		}
	}
	if mapsSecIndex < 0 {
		return nil, nil, nil, fmt.Errorf("could not determine index for .maps section")
	}

	if mapsSec != nil {
		syms, err := ef.Symbols()
		if err == nil {
			for _, sym := range syms {
				if int(sym.Section) == mapsSecIndex {
					if sym.Name == ".rodata" || sym.Name == ".bss" {
						continue
					}
					maps = append(maps, MapDesc{
						Name: sym.Name,
						Type: "TODO",
					})
				}
			}
		}
	}

	// Load programs
	for _, sec := range ef.Sections {
		// Check if the section is of type SHT_PROGBITS and has the executable flag set
		if sec.Type != elf.SHT_PROGBITS || (sec.Flags&elf.SHF_EXECINSTR) == 0 {
			continue
		}

		data, err := sec.Data()
		if err != nil {
			log.Printf("failed to get section data for %s: %v", sec.Name, err)
			continue
		}

		prog := ProgramDesc{
			Section:  sec.Name,
			Bytecode: data,
		}
		programs = append(programs, prog)
	}

	return sections, maps, programs, nil
}

// with cilium/ebpf 

// func LoadEbpfModule(ebpfBlob []byte) ([]string, []MapDesc, []ProgramDesc, error) {
// 	var sections []string
// 	var maps []MapDesc
// 	var programs []ProgramDesc

// 	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfBlob))
// 	if err != nil {
// 		return nil, nil, nil, fmt.Errorf("failed to load collection spec: %w", err)
// 	}

// 	ef, err := elf.NewFile(bytes.NewReader(ebpfBlob))
// 	if err != nil {
// 		return nil, nil, nil, fmt.Errorf("failed to parse ELF: %w", err)
// 	}

// 	for _, sec := range ef.Sections {
// 		sections = append(sections, sec.Name)
// 	}

// 	for name, m := range spec.Maps {
// 		if name == ".rodata" || name == ".bss" {
// 			continue
// 		}
// 		maps = append(maps, MapDesc{
// 			Name: name,
// 			Type: m.Type.String(),
// 		})
// 	}

// 	for _, p := range spec.Programs {
// 		programs = append(programs, ProgramDesc{
// 			Section:  p.SectionName,
// 			Bytecode: []byte(fmt.Sprintf("%v", p.Instructions.String())),
// 		})
// 	}
// 	return sections, maps, programs, nil
// }

// LoadWasmModule loads the wasm module.
func LoadWasmModule(ctx context.Context, wasmBytes []byte) (string, []string, error) {
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)
	runtimeConfig := wazero.NewRuntimeConfig()
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)

	// Compile the module
	module, err := runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		log.Fatalf("Failed to compile WASM module: %v", err)
	}

	// Iterate over the imports and print them
	imports := module.ImportedFunctions()
	upcalls := []string{}
	for _, imp := range imports {
		parts := strings.Split(imp.Name(), ".")
		upcalls = append(upcalls, parts[len(parts)-1])
	}

	// Hardcoded for now , I need to find a way to get the version from the wasm module get the version from the wasm module
	// TODO: export THE 'GadgetApiVersion' function and run it
	version := "TODO"

	return version, upcalls, nil
}

// GetGadgetParams extracts the gadget config from gadget.yaml.
func GetGadgetConfig(index *ocispec.Index) (Config, error) {
	rootURL := index.Annotations["org.opencontainers.image.source"]
	url := rootURL + "/gadget.yaml"
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			query := req.URL.Query()
			query.Set("raw", "true")
			req.URL.RawQuery = query.Encode()
			return nil
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return Config{}, fmt.Errorf("failed to fetch YAML: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Config{}, fmt.Errorf("received non-200 response: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read response body: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("failed to parse YAML: %v", err)
	}
	return config, nil
}
