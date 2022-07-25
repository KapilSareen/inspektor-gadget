// Copyright 2019-2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package snapshot

import (
	"github.com/spf13/cobra"

	commonsnapshot "github.com/kinvolk/inspektor-gadget/cmd/common/snapshot"
	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
)

func newProcessCmd() *cobra.Command {
	var processFlags commonsnapshot.ProcessFlags

	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print. Notice they may be
			// extended based on flags.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"comm",
				"pid",
			},
		},
	}

	availableColumns := map[string]struct{}{
		"node":      {},
		"namespace": {},
		"pod":       {},
		"container": {},
		"comm":      {},
		"tgid":      {},
		"pid":       {},
	}

	customRun := func(callback func(traceOutputMode string, results []string) error) error {
		config := NewSnapshotTraceConfig(commonsnapshot.ProcessGadgetName, commonFlags, nil)
		return utils.RunTraceAndPrintStatusOutput(config, callback)
	}

	// It is not currently useful to pass processFlags here but it keeps
	// uniformity with other gadgets.
	cmd := commonsnapshot.NewCommonProcessCmd(&processFlags, availableColumns, &commonFlags.OutputConfig, customRun)
	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}