// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type traceloopSyscallEventContT struct {
	Param              [128]uint8
	MonotonicTimestamp uint64
	Length             uint64
	Index              uint8
	Failed             uint8
	_                  [6]byte
}

type traceloopSyscallEventT struct {
	Args               [6]uint64
	MonotonicTimestamp uint64
	BootTimestamp      uint64
	Pid                uint32
	Cpu                uint16
	Id                 uint16
	Comm               [16]uint8
	ContNr             uint8
	Typ                uint8
	_                  [6]byte
}

// loadTraceloop returns the embedded CollectionSpec for traceloop.
func loadTraceloop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TraceloopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load traceloop: %w", err)
	}

	return spec, err
}

// loadTraceloopObjects loads traceloop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*traceloopObjects
//	*traceloopPrograms
//	*traceloopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTraceloopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTraceloop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// traceloopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type traceloopSpecs struct {
	traceloopProgramSpecs
	traceloopMapSpecs
	traceloopVariableSpecs
}

// traceloopProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type traceloopProgramSpecs struct {
	IgTraceloopE *ebpf.ProgramSpec `ebpf:"ig_traceloop_e"`
	IgTraceloopX *ebpf.ProgramSpec `ebpf:"ig_traceloop_x"`
}

// traceloopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type traceloopMapSpecs struct {
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
	MapOfPerfBuffers     *ebpf.MapSpec `ebpf:"map_of_perf_buffers"`
	ProbeAtSysExit       *ebpf.MapSpec `ebpf:"probe_at_sys_exit"`
	RegsMap              *ebpf.MapSpec `ebpf:"regs_map"`
	SyscallFilters       *ebpf.MapSpec `ebpf:"syscall_filters"`
	Syscalls             *ebpf.MapSpec `ebpf:"syscalls"`
}

// traceloopVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type traceloopVariableSpecs struct {
	PARAM_PROBE_AT_EXIT_MASK           *ebpf.VariableSpec `ebpf:"PARAM_PROBE_AT_EXIT_MASK"`
	SYSCALL_EVENT_TYPE_ENTER           *ebpf.VariableSpec `ebpf:"SYSCALL_EVENT_TYPE_ENTER"`
	SYSCALL_EVENT_TYPE_EXIT            *ebpf.VariableSpec `ebpf:"SYSCALL_EVENT_TYPE_EXIT"`
	USE_ARG_INDEX_AS_PARAM_LENGTH      *ebpf.VariableSpec `ebpf:"USE_ARG_INDEX_AS_PARAM_LENGTH"`
	USE_ARG_INDEX_AS_PARAM_LENGTH_MASK *ebpf.VariableSpec `ebpf:"USE_ARG_INDEX_AS_PARAM_LENGTH_MASK"`
	USE_NULL_BYTE_LENGTH               *ebpf.VariableSpec `ebpf:"USE_NULL_BYTE_LENGTH"`
	USE_RET_AS_PARAM_LENGTH            *ebpf.VariableSpec `ebpf:"USE_RET_AS_PARAM_LENGTH"`
	FilterSyscall                      *ebpf.VariableSpec `ebpf:"filter_syscall"`
	GadgetFilterByMntns                *ebpf.VariableSpec `ebpf:"gadget_filter_by_mntns"`
	UnusedEvent                        *ebpf.VariableSpec `ebpf:"unused_event"`
	UnusedEventCont                    *ebpf.VariableSpec `ebpf:"unused_event_cont"`
}

// traceloopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTraceloopObjects or ebpf.CollectionSpec.LoadAndAssign.
type traceloopObjects struct {
	traceloopPrograms
	traceloopMaps
	traceloopVariables
}

func (o *traceloopObjects) Close() error {
	return _TraceloopClose(
		&o.traceloopPrograms,
		&o.traceloopMaps,
	)
}

// traceloopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTraceloopObjects or ebpf.CollectionSpec.LoadAndAssign.
type traceloopMaps struct {
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
	MapOfPerfBuffers     *ebpf.Map `ebpf:"map_of_perf_buffers"`
	ProbeAtSysExit       *ebpf.Map `ebpf:"probe_at_sys_exit"`
	RegsMap              *ebpf.Map `ebpf:"regs_map"`
	SyscallFilters       *ebpf.Map `ebpf:"syscall_filters"`
	Syscalls             *ebpf.Map `ebpf:"syscalls"`
}

func (m *traceloopMaps) Close() error {
	return _TraceloopClose(
		m.GadgetMntnsFilterMap,
		m.MapOfPerfBuffers,
		m.ProbeAtSysExit,
		m.RegsMap,
		m.SyscallFilters,
		m.Syscalls,
	)
}

// traceloopVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadTraceloopObjects or ebpf.CollectionSpec.LoadAndAssign.
type traceloopVariables struct {
	PARAM_PROBE_AT_EXIT_MASK           *ebpf.Variable `ebpf:"PARAM_PROBE_AT_EXIT_MASK"`
	SYSCALL_EVENT_TYPE_ENTER           *ebpf.Variable `ebpf:"SYSCALL_EVENT_TYPE_ENTER"`
	SYSCALL_EVENT_TYPE_EXIT            *ebpf.Variable `ebpf:"SYSCALL_EVENT_TYPE_EXIT"`
	USE_ARG_INDEX_AS_PARAM_LENGTH      *ebpf.Variable `ebpf:"USE_ARG_INDEX_AS_PARAM_LENGTH"`
	USE_ARG_INDEX_AS_PARAM_LENGTH_MASK *ebpf.Variable `ebpf:"USE_ARG_INDEX_AS_PARAM_LENGTH_MASK"`
	USE_NULL_BYTE_LENGTH               *ebpf.Variable `ebpf:"USE_NULL_BYTE_LENGTH"`
	USE_RET_AS_PARAM_LENGTH            *ebpf.Variable `ebpf:"USE_RET_AS_PARAM_LENGTH"`
	FilterSyscall                      *ebpf.Variable `ebpf:"filter_syscall"`
	GadgetFilterByMntns                *ebpf.Variable `ebpf:"gadget_filter_by_mntns"`
	UnusedEvent                        *ebpf.Variable `ebpf:"unused_event"`
	UnusedEventCont                    *ebpf.Variable `ebpf:"unused_event_cont"`
}

// traceloopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTraceloopObjects or ebpf.CollectionSpec.LoadAndAssign.
type traceloopPrograms struct {
	IgTraceloopE *ebpf.Program `ebpf:"ig_traceloop_e"`
	IgTraceloopX *ebpf.Program `ebpf:"ig_traceloop_x"`
}

func (p *traceloopPrograms) Close() error {
	return _TraceloopClose(
		p.IgTraceloopE,
		p.IgTraceloopX,
	)
}

func _TraceloopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed traceloop_arm64_bpfel.o
var _TraceloopBytes []byte
