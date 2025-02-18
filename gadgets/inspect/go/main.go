//go:build js && wasm

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"syscall/js"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/inspect"
	"gopkg.in/yaml.v2"
)

// ProcessResult aggregates all the processed information.
type ProcessResult struct {
	Repository     string `json:"repository"`
	Tag            string `json:"tag"`
	Digest         string `json:"digest"`
	Created        string `json:"created"`
	EbpfInfo       string `json:"ebpfInfo"`
	WasmInfo       string `json:"wasmInfo"`
	GadgetYamlInfo string `json:"gadgetYamlInfo"`
	LayersAndArch  string `json:"LayersAndArchitectures"`
}

// ParseTarFromBytes processes tar data from a byte slice and returns:
//   - ebpfBlob: content of the ELF binary,
//   - wasmBlob: content of the WASM binary,
//   - gadgetYaml: content of the gadget YAML,
//   - indexInfos: slice of JSON snippets from remaining files.
func ParseTarFromBytes(data []byte) (ebpfBlob, wasmBlob, gadgetYaml []byte, indexInfos []json.RawMessage, err error) {
	r := bytes.NewReader(data)
	tarReader := tar.NewReader(r)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive.
		}
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("error reading tar file: %w", err)
		}

		// Process only regular files.
		if header.Typeflag != tar.TypeReg {
			continue
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("error reading content of %s: %w", header.Name, err)
		}

		switch {
		case bytes.HasPrefix(content, []byte("\x7FELF")):
			ebpfBlob = content
		case bytes.HasPrefix(content, []byte("\x00asm")):
			wasmBlob = content
		case strings.HasPrefix(string(content), "name:"):
			gadgetYaml = content
		default:
			indexInfos = append(indexInfos, json.RawMessage(content))
		}
	}
	return
}

// extractIndexData unmarshals combined JSON into a slice of maps.
func extractIndexData(combinedJSON []byte) ([]map[string]interface{}, error) {
	var indexItems []map[string]interface{}
	err := json.Unmarshal(combinedJSON, &indexItems)
	return indexItems, err
}

// getDataFromIndex extracts layers info, tags, architectures, digest, and created time
// from the index items.
func getDataFromIndex(indexItems []map[string]interface{}) (layersOutput, tagsOutput, archOutput string, digest string, createdTime string) {
	var layersBuilder, tagsBuilder, archBuilder strings.Builder
	archSet := make(map[string]struct{})
	tagSet := make(map[string]struct{})

	for _, item := range indexItems {
		// Process manifests: extract architectures, tags, created time, and digest.
		if manifests, ok := item["manifests"].([]interface{}); ok {
			for _, m := range manifests {
				manifestMap, ok := m.(map[string]interface{})
				if !ok {
					continue
				}

				// Extract architecture.
				if platform, ok := manifestMap["platform"].(map[string]interface{}); ok {
					if arch, ok := platform["architecture"].(string); ok {
						archSet[arch] = struct{}{}
					}
				}
				// Extract tag from annotations.
				if annotations, ok := manifestMap["annotations"].(map[string]interface{}); ok {
					if refName, ok := annotations["org.opencontainers.image.ref.name"].(string); ok {
						tagSet[refName] = struct{}{}
					}
					// Extract created time.
					if created, ok := annotations["org.opencontainers.image.created"].(string); ok {
						createdTime = created
					}
				}
				// Extract digest for index media type.
				if mediaType, ok := manifestMap["mediaType"].(string); ok && mediaType == "application/vnd.oci.image.index.v1+json" {
					if d, ok := manifestMap["digest"].(string); ok {
						digest = d
					}
				}
			}
		}
		// Process layers.
		if layers, ok := item["layers"].([]interface{}); ok {
			layersBuilder.WriteString("Layers:\n")
			for _, l := range layers {
				if layerMap, ok := l.(map[string]interface{}); ok {
					mediaType, _ := layerMap["mediaType"].(string)
					layersBuilder.WriteString(fmt.Sprintf("\tMediaType: %s\n", mediaType))
				}
			}
		}
	}

	// Build tags output.
	for tag := range tagSet {
		tagsBuilder.WriteString(tag + "\n")
	}

	// Build architectures output.
	archBuilder.WriteString("Architectures:\n")
	for arch := range archSet {
		archBuilder.WriteString("\t"+arch + "\n")
	}

	return layersBuilder.String(), tagsBuilder.String(), archBuilder.String(), digest, createdTime
}

// processTar is the exported function called from JavaScript.
// It expects one argument: a Uint8Array containing tar file data.
func processTar(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf("Error: expected one argument (Uint8Array)")
	}

	// Convert JS Uint8Array to Go []byte.
	length := args[0].Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, args[0])

	// Parse tar file.
	ebpfBlob, wasmBlob, gadgetYaml, indexInfos, err := ParseTarFromBytes(buf)
	if err != nil {
		return js.ValueOf("Error processing tar: " + err.Error())
	}
	if ebpfBlob == nil || wasmBlob == nil {
		return js.ValueOf("Error: required blobs not found in tar")
	}

	// Process eBPF module.
	ebpfInfo := ""
	sections, maps, programs, err := inspect.LoadEbpfModule(ebpfBlob)
	if err != nil {
		ebpfInfo = "Error loading eBPF module: " + err.Error()
	} else {
		var mapNames []string
		for _, m := range maps {
			mapNames = append(mapNames, m.Name)
		}
		ebpfInfo = fmt.Sprintf("\n\tSections: %v\n\tMaps: %v\n\t", sections, mapNames)
		if len(programs) > 0 {
			var programSections []string
			for _, program := range programs {
				programSections = append(programSections, program.Section)
			}
			ebpfInfo += fmt.Sprintf("Programs: %v", programSections)
		}
	}

	// Process WASM module.
	ctx := context.Background()
	wasmInfo := ""
	gadgetApiVersion, upcalls, err := inspect.LoadWasmModule(ctx, wasmBlob)
	if err != nil {
		wasmInfo = "Error loading WASM module: " + err.Error()
	} else {
		wasmInfo = fmt.Sprintf("\n\tGadget API Version: %v\n\tUpcalls: %v", gadgetApiVersion, upcalls)
	}

	// Process gadget YAML.
	gadgetYamlInfo := ""
	var config inspect.Config
	if err := yaml.Unmarshal(gadgetYaml, &config); err != nil {
		gadgetYamlInfo = "Error parsing gadget.yaml: " + err.Error()
	} else {
		var ebpfParams []string
		if params, exists := config.Params["ebpf"]; exists {
			for paramName := range params {
				ebpfParams = append(ebpfParams, paramName)
			}
		}
		var datasourceFields []string
		for _, ds := range config.Datasources {
			for fieldName := range ds.Fields {
				datasourceFields = append(datasourceFields, fieldName)
			}
		}
		gadgetYamlInfo = fmt.Sprintf("\n\tEBPF Params: %v\n\tDatasource Fields: %v", ebpfParams, datasourceFields)
	}

	// Combine indexInfos JSON snippets into a single JSON array.
	combinedIndexJSON, err := json.MarshalIndent(indexInfos, "", "  ")

	// Extract layers and architectures from the index data.
	indexItems, err := extractIndexData(combinedIndexJSON)
	var layers, tags, arch, digest, created string
	if err == nil {
		layers, tags, arch, digest, created = getDataFromIndex(indexItems)
	}
	extractedLayersAndArch := fmt.Sprintf("\n%s%s", layers, arch)

	// Use the first tag from tags output if available.
	var repo, tag string
	if strings.Contains(tags, ":") {
		parts := strings.SplitN(tags, ":", 2)
		repo = parts[0]
		tag = parts[1]
	}

	result := ProcessResult{
		Repository:     repo,
		Tag:            tag,
		Digest:         digest,
		Created:        created,
		EbpfInfo:       ebpfInfo,
		WasmInfo:       wasmInfo,
		GadgetYamlInfo: gadgetYamlInfo,
		LayersAndArch:  extractedLayersAndArch,
	}

	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return js.ValueOf("Error marshaling final result: " + err.Error())
	}
	return js.ValueOf(string(resultJSON))
}

func main() {
	js.Global().Set("processTar", js.FuncOf(processTar))
	// Prevent exit.
	select {}
}
