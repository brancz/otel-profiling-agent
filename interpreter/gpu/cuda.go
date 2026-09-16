package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unique"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	// eBPF program names for USDT probes
	// These correspond to the function names in cuda.ebpf.c, not the SEC() paths
	USDTProgCudaCorrelation       = "cuda_correlation"
	USDTProgCudaKernel            = "cuda_kernel_exec"
	USDTProgCudaActivityBatch     = "cuda_activity_batch"
	USDTProgCudaActivityBatchTail = "cuda_activity_batch_tail"
	USDTProgCudaCubinLoaded       = "cuda_cubin_loaded"
	USDTProgCudaPCSampleBatch     = "cuda_pc_sample_batch"
	USDTProgCudaPCSampleBatchTail = "cuda_pc_sample_batch_tail"
	USDTProgCudaStallReasonMap    = "cuda_stall_reason_map"
	USDTProgCudaError             = "cuda_error"
	USDTProgCudaGpuConfig         = "cuda_gpu_config"
	USDTProgCudaProbe             = "cuda_probe"

	// BPF attach cookie values - must match CUDA_PROG_* in cuda.ebpf.c.
	// Used in the low 32 bits of the BPF attach cookie so cuda_probe can
	// distinguish probes.  The cuda_progs prog array uses keys 0
	// (activity_batch) and 1 (pc_sample_batch) for tail-call dispatch of heavy
	// loops; everything else is inlined directly in cuda_probe.  The
	// pc_sample_batch program additionally tail-chains into itself (slot 1) up
	// to BPF_PC_MAX_TAIL_CALLS times to process batches larger than one chunk
	// while keeping each program under the 1M-insn verifier complexity cap.
	CudaProgCorrelation    = 0
	CudaProgKernelExec     = 1
	CudaProgActivityBatch  = 2
	CudaProgCubinLoaded    = 3
	CudaProgPCSampleBatch  = 4
	CudaProgStallReasonMap = 5
	CudaProgError          = 6
	CudaProgGpuConfig      = 7
)

const cudaProgsMap = "cuda_progs"

// Event type discriminators for the cupti_events ringbuf. Must match the
// EVENT_TYPE_* constants in support/ebpf/cuda.ebpf.c.
const (
	EventTypeKernel         uint32 = 1
	EventTypeCubinLoaded    uint32 = 2
	EventTypePCSample       uint32 = 3
	EventTypeStallReasonMap uint32 = 4
	EventTypeError          uint32 = 5
	EventTypeGpuConfig      uint32 = 6
)

// CuptiCubinEvent matches struct cubin_event in cuda.ebpf.c.
// TODO: get rid of these definitions and generate them from C.
type CuptiCubinEvent struct {
	EventType uint32
	Pid       uint32
	CubinCRC  uint64
	CubinPtr  uint64
	CubinSize uint64
}

// CuptiPCData mirrors struct cupti_pc_data in cupti_bpf.h (parcagpu).  It is
// 56 bytes, packed but with all fields naturally aligned so a plain Go struct
// matches the C byte layout.  Only CubinCRC, PCOffset, FunctionIndex and
// StallReasonCount are consumed on the Go side; the rest are anonymous padding
// placeholders so the single-shot bpf_probe_read_user lands the consumed fields
// at the right offsets.  The function-name and stall-reason pointers are used
// by BPF in-kernel before the event is submitted to the ringbuf.
type CuptiPCData struct {
	_                uint64 // size
	CubinCRC         uint64
	PCOffset         uint64
	FunctionIndex    uint32 // CUPTI's per-module function id; logged for correlation
	_                uint32 // _pc_pad
	_                uint64 // function_name_ptr (used by BPF only)
	StallReasonCount uint64
	_                uint64 // stall_reason_ptr (used by BPF only)
}

// CuptiPCSampleEvent matches struct pc_sample_event in cuda.ebpf.c.  Data +
// CorrelationID receive the producer's 60-byte CUDA 12.4+ pc-sampling record
// via a single bpf_probe_read_user.
type CuptiPCSampleEvent struct {
	EventType     uint32
	Pid           uint32
	Data          CuptiPCData
	CorrelationID uint32
	DeviceID      uint32 // device the collecting CUcontext is bound to; see parcagpu's ConfigureData.device
	FunctionName  [128]byte
	StallReasons  [64]CuptiStallReason
}

// CuptiStallReason matches struct cupti_stall_reason in cupti_bpf.h.
type CuptiStallReason struct {
	Index   uint32
	Samples uint32
}

// CuptiStallReasonMapEvent matches struct stall_reason_map_event in cuda.ebpf.c.
type CuptiStallReasonMapEvent struct {
	EventType uint32
	Count     uint32
	Pid       uint32
	_pad      uint32
	Names     [64][64]byte
}

// CuptiErrorEvent matches struct error_event in cuda.ebpf.c.
type CuptiErrorEvent struct {
	EventType uint32
	Code      int32
	Pid       uint32
	_pad      uint32
	Message   [256]byte
	Component [64]byte
}

// CuptiGpuConfigEvent matches struct gpu_config_event in cuda.ebpf.c.
type CuptiGpuConfigEvent struct {
	EventType      uint32
	Pid            uint32
	DeviceID       uint32
	SamplingFactor uint32
	ClockKHz       uint32
	SMCount        uint32
}

var (
	// gpuFixers maps PID to gpuTraceFixer
	gpuFixers sync.Map
)

// SymbolizedCudaTrace holds a symbolized trace awaiting GPU timing information.
// The CPU frames are already symbolized; only the CUDA kernel frame
// needs the kernel name from the timing event.
type SymbolizedCudaTrace struct {
	Trace         *libpf.Trace
	Meta          *samples.TraceEventMeta
	CUDAFrameIdx  int // index of CUDAKernelFrame in Trace.Frames
	CorrelationID uint32
	CBID          int32
	// StoredAtNs is time.Now().UnixNano() at the moment this trace first entered
	// pcTraces/tracesAwaitingTimes. Used to measure wait time when the timing
	// event arrives, or age at eviction. Unset when StoredAtNs is 0.
	StoredAtNs int64
}

// CudaTraceOutput is a fully completed CUDA trace ready for reporting.
// For non-graph launches the pointers alias the SymbolizedCudaTrace directly.
// For graph launches they point to copies since the original is reused.
type CudaTraceOutput struct {
	Trace *libpf.Trace
	Meta  *samples.TraceEventMeta
}

// gpuTraceFixer matches traces with timing information for a specific PID.
// We use a single fixer per PID because CUDA correlation IDs are unique per process
// across all devices and streams.
// See: https://docs.nvidia.com/cupti/api/structCUpti__ActivityKernel.html
// The correlationId field: "Each function invocation is assigned a unique correlation ID
// that is identical to the correlation ID in the driver or runtime API activity record
// that launched the kernel."
type gpuTraceFixer struct {
	mu                  sync.Mutex
	timesAwaitingTraces map[uint32][]CuptiKernelEvent   // keyed by correlation ID
	tracesAwaitingTimes map[uint32]*SymbolizedCudaTrace // keyed by correlation ID
	maxCorrelationId    uint32                          // track highest ID for threshold-based clearing

	// timesStoredAtNs holds the UnixNano timestamp when the FIRST entry for
	// each correlation ID landed in timesAwaitingTraces. Parallel map, same key.
	// Used to measure how long the timing event waited for its trace.
	timesStoredAtNs map[uint32]int64

	// pcTraces keeps recently received traces available for PC sample correlation.
	// Unlike tracesAwaitingTimes, entries here are not consumed when timing arrives.
	// Cleaned up by the same threshold-based logic in maybeClear.
	pcTraces map[uint32]*SymbolizedCudaTrace

	// pendingPCSamples stores PC samples that arrived before their correlation
	// trace. Resolved when addSingleTrace/addGraphTrace stores the trace.
	pendingPCSamples map[uint32][]pendingPCSample

	// pcSampleHasDevice is whether this pid's pc_sample_batch probe carries the
	// deviceId argument (resolved once at Attach); false omits cuda_device instead of reporting device 0.
	pcSampleHasDevice bool
}

type pendingPCSample struct {
	ev        CuptiPCSampleEvent
	rep       reporter.TraceReporter
	arrivalNs int64 // time.Now().UnixNano() when this sample was buffered
}

func newGpuTraceFixer(pcSampleHasDevice bool) *gpuTraceFixer {
	return &gpuTraceFixer{
		timesAwaitingTraces: make(map[uint32][]CuptiKernelEvent),
		tracesAwaitingTimes: make(map[uint32]*SymbolizedCudaTrace),
		timesStoredAtNs:     make(map[uint32]int64),
		pcTraces:            make(map[uint32]*SymbolizedCudaTrace),
		pendingPCSamples:    make(map[uint32][]pendingPCSample),
		pcSampleHasDevice:   pcSampleHasDevice,
	}
}

type linkEntry struct {
	link interpreter.LinkCloser
	refs int
}

type data struct {
	path           string
	probes         []pfelf.USDTProbe
	kernelFallback *pfelf.USDTProbe // kernel_executed probe, kept as fallback if activity_batch fails

	links map[util.OnDiskFileIdentifier]*linkEntry // uprobe attachments keyed by inode
}

// Instance is the CUDA interpreter instance
type Instance struct {
	interpreter.InstanceStubs
	d    *data
	path string
	pid  libpf.PID
	odfi util.OnDiskFileIdentifier
}

// CuptiKernelEvent is the kernel-timing event received from eBPF via the
// cupti_events ringbuf. The first field is the EVENT_TYPE_KERNEL discriminator
// shared by every event submitted on cupti_events. Layout must match
// struct kernel_event in support/ebpf/cuda.ebpf.c.
type CuptiKernelEvent struct {
	EventType               uint32
	Pid                     uint32
	Start, End, GraphNodeId uint64
	Id                      uint32
	Dev, Stream, Graph      uint32
	KernelName              [256]byte
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// We use the existence of the .note.stapsdt section to determine if this is a
	// process that has libparcagpucupti.so loaded.
	probes, err := ef.ParseUSDTProbes()
	if err != nil {
		return nil, err
	}
	if len(probes) > 0 {
		var parcagpuProbes []pfelf.USDTProbe
		for _, probe := range probes {
			if probe.Provider == "parcagpu" {
				parcagpuProbes = append(parcagpuProbes, probe)
			}
		}
		if len(parcagpuProbes) == 0 {
			return nil, nil
		}

		// Filter to the probes we know how to handle.
		// Always require cuda_correlation. Prefer activity_batch over kernel_executed.
		// cubin_loaded, pc_sample_batch, stall_reason_map and error are optional —
		// attached opportunistically when present.
		var correlationProbe *pfelf.USDTProbe
		var kernelProbe *pfelf.USDTProbe
		var batchProbe *pfelf.USDTProbe
		var cubinProbe *pfelf.USDTProbe
		var pcSampleProbe *pfelf.USDTProbe
		var stallMapProbe *pfelf.USDTProbe
		var errorProbe *pfelf.USDTProbe
		var gpuConfigProbe *pfelf.USDTProbe
		for i := range parcagpuProbes {
			switch parcagpuProbes[i].Name {
			case "cuda_correlation":
				correlationProbe = &parcagpuProbes[i]
			case "kernel_executed":
				kernelProbe = &parcagpuProbes[i]
			case "activity_batch":
				batchProbe = &parcagpuProbes[i]
			case "cubin_loaded":
				cubinProbe = &parcagpuProbes[i]
			case "pc_sample_batch":
				pcSampleProbe = &parcagpuProbes[i]
			case "stall_reason_map":
				stallMapProbe = &parcagpuProbes[i]
			case "error":
				errorProbe = &parcagpuProbes[i]
			case "gpu_config":
				gpuConfigProbe = &parcagpuProbes[i]
			}
		}
		if correlationProbe == nil {
			log.Warnf("parcagpu USDT probes in %s missing cuda_correlation: %v", info.FileName(), parcagpuProbes)
			return nil, nil
		}

		var requiredProbes []pfelf.USDTProbe
		requiredProbes = append(requiredProbes, *correlationProbe)
		if batchProbe != nil {
			requiredProbes = append(requiredProbes, *batchProbe)
			log.Debugf("parcagpu: using activity_batch mode for %s", info.FileName())
		} else if kernelProbe != nil {
			requiredProbes = append(requiredProbes, *kernelProbe)
			log.Debugf("parcagpu: using kernel_executed mode for %s", info.FileName())
		} else {
			log.Warnf("parcagpu USDT probes in %s missing kernel probe (need activity_batch or kernel_executed): %v", info.FileName(), parcagpuProbes)
			return nil, nil
		}
		if cubinProbe != nil {
			requiredProbes = append(requiredProbes, *cubinProbe)
		}
		if pcSampleProbe != nil {
			requiredProbes = append(requiredProbes, *pcSampleProbe)
		}
		if stallMapProbe != nil {
			requiredProbes = append(requiredProbes, *stallMapProbe)
		}
		if errorProbe != nil {
			requiredProbes = append(requiredProbes, *errorProbe)
		}
		if gpuConfigProbe != nil {
			requiredProbes = append(requiredProbes, *gpuConfigProbe)
		}
		parcagpuProbes = requiredProbes

		log.Debugf("Found parcagpu USDT probes in %s: %v", info.FileName(), parcagpuProbes)

		d := &data{
			path:   info.FileName(),
			probes: parcagpuProbes,
		}
		// If using activity_batch, keep kernel_executed as fallback in case
		// the tail-call prog array setup fails (e.g. verifier rejection).
		if batchProbe != nil && kernelProbe != nil {
			d.kernelFallback = kernelProbe
		}

		return d, nil
	}
	return nil, nil
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (interpreter.Instance, error) {
	// Populate the cuda_progs tail-call array. UpdateProgArray is idempotent
	// (programs are cached, map updates are atomic), so it is safe to call on
	// every Attach. activity_batch failure falls back to kernel_executed;
	// pc_sample_batch failure just drops the pc sample probe.
	for i, probe := range d.probes {
		if probe.Name != "activity_batch" {
			continue
		}
		if err := ebpf.UpdateProgArray(cudaProgsMap, 0,
			USDTProgCudaActivityBatchTail); err != nil {
			log.Errorf("[cuda] activity_batch tail call failed: %v", err)
			if d.kernelFallback != nil {
				d.probes[i] = *d.kernelFallback
				log.Warnf("[cuda] falling back to kernel_executed mode")
			} else {
				log.Errorf("[cuda] activity_batch failed and no kernel_executed fallback")
				d.probes = append(d.probes[:i], d.probes[i+1:]...)
			}
		}
		break
	}
	for i := 0; i < len(d.probes); {
		if d.probes[i].Name != "pc_sample_batch" {
			i++
			continue
		}
		if err := ebpf.UpdateProgArray(cudaProgsMap, 1,
			USDTProgCudaPCSampleBatchTail); err != nil {
			log.Errorf("[cuda] pc_sample_batch tail call failed: %v — dropping pc_sample_batch", err)
			d.probes = append(d.probes[:i], d.probes[i+1:]...)
			continue
		}
		i++
	}

	// Map USDT probe names to eBPF program names and cookies.
	// The cookie tells cuda_probe which inlined branch (or tail call) to take.
	cookies := make([]uint64, len(d.probes))
	progNames := make([]string, len(d.probes))
	for i, probe := range d.probes {
		switch probe.Name {
		case "cuda_correlation":
			cookies[i] = CudaProgCorrelation
			progNames[i] = USDTProgCudaCorrelation
		case "kernel_executed":
			cookies[i] = CudaProgKernelExec
			progNames[i] = USDTProgCudaKernel
		case "activity_batch":
			cookies[i] = CudaProgActivityBatch
			progNames[i] = USDTProgCudaActivityBatch
		case "cubin_loaded":
			cookies[i] = CudaProgCubinLoaded
			progNames[i] = USDTProgCudaCubinLoaded
		case "pc_sample_batch":
			cookies[i] = CudaProgPCSampleBatch
			progNames[i] = USDTProgCudaPCSampleBatch
		case "stall_reason_map":
			cookies[i] = CudaProgStallReasonMap
			progNames[i] = USDTProgCudaStallReasonMap
		case "error":
			cookies[i] = CudaProgError
			progNames[i] = USDTProgCudaError
		case "gpu_config":
			cookies[i] = CudaProgGpuConfig
			progNames[i] = USDTProgCudaGpuConfig
		default:
			log.Debugf("unknown parcagpu USDT probe name: %s", probe.Name)
		}
	}

	// Stat the path via /proc/<pid>/root so this works when parca-agent runs
	// in a container that doesn't share the target's mount namespace. The
	// subsequent AttachUSDTProbes call already opens the file via the same
	// /proc/<pid>/root prefix.
	containerPath := "/proc/" + strconv.Itoa(int(pid)) + "/root/" + d.path
	st, err := os.Stat(containerPath)
	if err != nil {
		return nil, fmt.Errorf("[cuda] stat %s: %w", containerPath, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return nil, fmt.Errorf("[cuda] failed to get stat_t for %s", containerPath)
	}
	key := util.OnDiskFileIdentifier{DeviceID: uint64(sys.Dev), InodeNum: uint64(sys.Ino)}

	if d.links == nil {
		d.links = make(map[util.OnDiskFileIdentifier]*linkEntry)
	}
	le := d.links[key]
	if le == nil {
		lc, err := ebpf.AttachUSDTProbes(pid, d.path, USDTProgCudaProbe, d.probes, cookies, progNames)
		if err != nil {
			return nil, err
		}
		le = &linkEntry{link: lc}
		d.links[key] = le
		log.Debugf("[cuda] parcagpu USDT probes attached for %s (dev=%d ino=%d)",
			d.path, key.DeviceID, key.InodeNum)
	}
	le.refs++

	var pcSampleHasDevice bool
	for _, probe := range d.probes {
		if probe.Name != "pc_sample_batch" {
			continue
		}
		spec, err := pfelf.ParseUSDTArguments(probe.Arguments)
		pcSampleHasDevice = err == nil && spec.Arg_cnt >= 3
		if err == nil && !pcSampleHasDevice {
			log.Warnf("[cuda] pid=%d: pc_sample_batch has %d args (need 3 for cuda_device) — "+
				"built from an older parcagpu; PC samples won't carry a cuda_device label",
				pid, spec.Arg_cnt)
		}
		break
	}

	gpuFixers.Store(pid, newGpuTraceFixer(pcSampleHasDevice))
	return &Instance{
		d:    d,
		path: d.path,
		pid:  pid,
		odfi: key,
	}, nil
}

func (i *Instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	gpuFixers.Delete(i.pid)
	DeleteStallReasonMap(uint32(i.pid))
	if le := i.d.links[i.odfi]; le != nil {
		le.refs--
		if le.refs <= 0 {
			log.Debugf("[cuda] last ref for %s (dev=%d ino=%d), unloading probes",
				i.d.path, i.odfi.DeviceID, i.odfi.InodeNum)
			if err := le.link.Unload(); err != nil {
				log.Errorf("error closing cuda usdt link: %s", err)
			}
			delete(i.d.links, i.odfi)
		}
	}
	return nil
}

const (
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch                = 514
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz           = 515
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000      = 311
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000 = 312
)

func isGraphLaunch(cbid int32) bool {
	if cbid < 0 {
		// Driver API callback ids are negative
		switch -cbid {
		case CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch, CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz:
			return true
		}
	} else {
		switch cbid {
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000, CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000:
			return true
		}
	}
	return false
}

// addSingleTrace handles non-graph CUDA launches. If timing already arrived it
// returns the completed output directly (no slice, no SymbolizedCudaTrace allocated).
// Otherwise it stores a SymbolizedCudaTrace for later matching.
func (f *gpuTraceFixer) addSingleTrace(trace *libpf.Trace, meta *samples.TraceEventMeta,
	cudaFrameIdx int, correlationID uint32, cbid int32) (CudaTraceOutput, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Update max, detecting wrap-around (new ID much smaller than max means wrap)
	if correlationID > f.maxCorrelationId || f.maxCorrelationId-correlationID > 1<<31 {
		f.maxCorrelationId = correlationID
	}

	// Always store for PC sample correlation, even if timing already arrived.
	nowNs := time.Now().UnixNano()
	st := &SymbolizedCudaTrace{
		Trace:         trace,
		Meta:          meta,
		CUDAFrameIdx:  cudaFrameIdx,
		CorrelationID: correlationID,
		CBID:          cbid,
		StoredAtNs:    nowNs,
	}
	f.pcTraces[correlationID] = st

	// Resolve any PC samples that arrived before this trace.  Emit all of them
	// from a single goroutine — spawning one per sample would burn scheduler
	// time when a hot kernel can buffer dozens-to-hundreds of samples.  We
	// still want a goroutine so we drop f.mu before rep.ReportTraceEvent.
	if pending, ok := f.pendingPCSamples[correlationID]; ok {
		delete(f.pendingPCSamples, correlationID)
		if waitLogEnabled {
			for i := range pending {
				logWait("pc_sample", "matched_deferred",
					nowNs-pending[i].arrivalNs, correlationID, pending[i].ev.Pid)
			}
		}
		go func(pending []pendingPCSample, st *SymbolizedCudaTrace) {
			for i := range pending {
				emitPCSample(&pending[i].ev, pending[i].rep, st)
			}
		}(pending, st)
	}

	evs, ok := f.timesAwaitingTraces[correlationID]
	if ok && len(evs) > 0 {
		log.Debugf("[cuda] gpu trace completed id %d cbid %d (0x%x) for pid %d",
			correlationID, int(cbid), uint32(cbid), meta.PID)
		if waitLogEnabled {
			if storedAt, ok := f.timesStoredAtNs[correlationID]; ok {
				logWait("time_to_trace", "matched", nowNs-storedAt,
					correlationID, uint32(meta.PID))
			}
		}
		out := f.prepTrace(trace, meta, cudaFrameIdx, &evs[0])
		delete(f.timesAwaitingTraces, correlationID)
		delete(f.timesStoredAtNs, correlationID)
		return out, true
	}

	// Store trace for future timing events (reuse the pcTraces entry).
	f.tracesAwaitingTimes[correlationID] = f.pcTraces[correlationID]
	return CudaTraceOutput{}, false
}

// addGraphTrace handles graph CUDA launches. Returns completed outputs for any
// timing events that arrived before this trace, and always stores the trace for
// future timing events (graphs can fire many kernels with the same correlation ID).
func (f *gpuTraceFixer) addGraphTrace(trace *libpf.Trace, meta *samples.TraceEventMeta,
	cudaFrameIdx int, correlationID uint32, cbid int32) []CudaTraceOutput {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Update max, detecting wrap-around (new ID much smaller than max means wrap)
	if correlationID > f.maxCorrelationId || f.maxCorrelationId-correlationID > 1<<31 {
		f.maxCorrelationId = correlationID
	}

	nowNs := time.Now().UnixNano()
	var outputs []CudaTraceOutput
	evs, ok := f.timesAwaitingTraces[correlationID]
	if ok && len(evs) > 0 {
		if waitLogEnabled {
			if storedAt, ok := f.timesStoredAtNs[correlationID]; ok {
				logWait("time_to_trace", "matched_graph", nowNs-storedAt,
					correlationID, uint32(meta.PID),
					fmt.Sprintf("n_times=%d", len(evs)))
			}
		}
		for idx := range evs {
			log.Debugf("[cuda] gpu trace completed id %d cbid %d (0x%x) for pid %d",
				correlationID, int(cbid), uint32(cbid), meta.PID)
			outputs = append(outputs, f.prepTrace(trace, meta, cudaFrameIdx, &evs[idx]))
		}
		delete(f.timesAwaitingTraces, correlationID)
		delete(f.timesStoredAtNs, correlationID)
	}

	// Always store for future timing events
	st := &SymbolizedCudaTrace{
		Trace:         trace,
		Meta:          meta,
		CUDAFrameIdx:  cudaFrameIdx,
		CorrelationID: correlationID,
		CBID:          cbid,
		StoredAtNs:    nowNs,
	}
	f.tracesAwaitingTimes[correlationID] = st
	f.pcTraces[correlationID] = st
	return outputs
}

// addTime is called when timing info is received from eBPF, to match it with a trace.
// Caller must hold f.mu.
func (f *gpuTraceFixer) addTime(ev *CuptiKernelEvent) (CudaTraceOutput, bool) {
	// Update max, detecting wrap-around (new ID much smaller than max means wrap)
	if ev.Id > f.maxCorrelationId || f.maxCorrelationId-ev.Id > 1<<31 {
		f.maxCorrelationId = ev.Id
	}

	st, ok := f.tracesAwaitingTimes[ev.Id]
	if ok {
		if waitLogEnabled {
			logWait("trace_to_time", "matched", time.Now().UnixNano()-st.StoredAtNs,
				ev.Id, ev.Pid)
		}
		if ev.Graph == 0 {
			delete(f.tracesAwaitingTimes, ev.Id)
		}
		return f.prepTrace(st.Trace, st.Meta, st.CUDAFrameIdx, ev), true
	}
	if _, exists := f.timesAwaitingTraces[ev.Id]; !exists {
		f.timesStoredAtNs[ev.Id] = time.Now().UnixNano()
	}
	f.timesAwaitingTraces[ev.Id] = append(f.timesAwaitingTraces[ev.Id], *ev)
	return CudaTraceOutput{}, false
}

// lookupTraceForPC returns the symbolized trace for a given correlation ID,
// if available. Used by PC sample processing to correlate GPU samples with
// CPU call stacks.
func (f *gpuTraceFixer) lookupTraceForPC(correlationID uint32) *SymbolizedCudaTrace {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st, ok := f.pcTraces[correlationID]; ok {
		return st
	}
	if st, ok := f.tracesAwaitingTimes[correlationID]; ok {
		return st
	}
	return nil
}

// LookupTraceForPCSample finds the CPU trace associated with a given PID and
// correlation ID for PC sample correlation.
func LookupTraceForPCSample(pid libpf.PID, correlationID uint32) *SymbolizedCudaTrace {
	value, ok := gpuFixers.Load(pid)
	if !ok {
		return nil
	}
	return value.(*gpuTraceFixer).lookupTraceForPC(correlationID)
}

// StorePendingPCSample buffers a PC sample whose correlation trace hasn't
// arrived yet. It will be emitted when the trace shows up in addSingleTrace.
func StorePendingPCSample(pid libpf.PID, ev CuptiPCSampleEvent, rep reporter.TraceReporter) {
	value, ok := gpuFixers.Load(pid)
	if !ok {
		// No fixer for this PID — emit without correlation.
		go emitPCSample(&ev, rep, nil)
		return
	}
	f := value.(*gpuTraceFixer)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pendingPCSamples[ev.CorrelationID] = append(
		f.pendingPCSamples[ev.CorrelationID],
		pendingPCSample{ev: ev, rep: rep, arrivalNs: time.Now().UnixNano()})
}

// emitPCSample is the deferred version of HandlePCSample, called when the
// correlation trace becomes available (or immediately if no fixer exists).
func emitPCSample(ev *CuptiPCSampleEvent, rep reporter.TraceReporter, cpuTrace *SymbolizedCudaTrace) {
	cubinInfo, ok := LoadCubin(ev.Data.CubinCRC)
	if !ok {
		return
	}
	// Transient: kernelName is interned (copied) before ev goes out of scope.
	kernelName := pfunsafe.ToString(nullTerm(ev.FunctionName[:]))

	// Decode the SASS instruction at this offset, surfaced as the
	// "cuda_sass_instruction" sample label.
	mnemonic := decodeInstruction(cubinInfo, kernelName, ev.Data.PCOffset)

	// One mapping per cubin: the build ID is the cubin CRC (FileID with lo=0).
	// The kernel's mangled name rides on the frame as its system name so the
	// backend can resolve it per function.
	cubinName := fmt.Sprintf("cubin-%016x", cubinInfo.CRC)
	cubinMapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:   cubinInfo.FileID,
			FileName: libpf.Intern(cubinName),
		}),
	})

	var hasDevice bool
	if value, ok := gpuFixers.Load(libpf.PID(ev.Pid)); ok {
		hasDevice = value.(*gpuTraceFixer).pcSampleHasDevice
	}

	// One sample per stall reason: the same single CUDAPCFrame, distinguished by
	// the "cuda_stall_reason" label and weighted by that reason's sample count.
	count := min(ev.Data.StallReasonCount, maxStallReasons)
	for i := range count {
		sr := ev.StallReasons[i]
		if sr.Samples == 0 {
			continue
		}

		trace := buildGpuPCTrace(cpuTrace, cubinMapping, kernelName, ev.Data.PCOffset)
		trace.CustomLabels = gpuPCLabels(LookupStallReason(ev.Pid, sr.Index), mnemonic, ev.DeviceID, hasDevice)

		meta := buildGpuPCMeta(cpuTrace, ev.Pid, int64(sr.Samples))
		if err := rep.ReportTraceEvent(trace, meta); err != nil {
			log.Errorf("[cuda] failed to report GPU PC sample: %v", err)
		}
	}
}

// fixerStats holds statistics from a single fixer for aggregation.
type fixerStats struct {
	timesLen              int
	tracesLen             int
	timesCleared          int
	tracesCleared         int
	pendingSamplesEvicted int
}

// Map-size thresholds for the per-fixer clearing sweep run from
// MaybeClearAll. Bumped 10x from the original 10000/5000 because the
// tighter values dropped late-arriving symbolized traces on
// high-launch-rate workloads (e.g. PyTorch ~5K kernels/sec). At those
// rates the retention window of 5K correlation IDs corresponds to
// only ~1 second of history, which is too short for the trace
// symbolization pipeline.
const (
	clearTriggerThreshold = 100000
	retentionWindow       = 50000
)

// waitLogEnabled gates the per-event [cudawait] log lines used to build
// post-hoc histograms of trace/sample wait times. Off by default (the volume
// can reach ~5K lines/sec on a heavy CUDA workload). Set PARCA_CUDA_WAIT_LOG=1
// to enable.
var waitLogEnabled = os.Getenv("PARCA_CUDA_WAIT_LOG") == "1"

// logWait emits a single fixed-format line consumed by
// scripts/cuda_wait_histograms.py. All durations are in nanoseconds. Extra
// key=value tokens may be appended; the parser ignores unknown keys.
//
// Format: "[cudawait] kind=<k> outcome=<o> wait_ns=<n> corr=<id> pid=<pid> <extra...>"
func logWait(kind, outcome string, waitNs int64, corrID uint32, pid uint32, extra ...string) {
	if !waitLogEnabled {
		return
	}
	if len(extra) == 0 {
		log.Infof("[cudawait] kind=%s outcome=%s wait_ns=%d corr=%d pid=%d",
			kind, outcome, waitNs, corrID, pid)
		return
	}
	// Pre-size the join buffer to avoid intermediate allocs.
	var sb bytes.Buffer
	fmt.Fprintf(&sb, "[cudawait] kind=%s outcome=%s wait_ns=%d corr=%d pid=%d",
		kind, outcome, waitNs, corrID, pid)
	for _, e := range extra {
		sb.WriteByte(' ')
		sb.WriteString(e)
	}
	log.Info(sb.String())
}

// maybeClear clears the maps if they get too big and returns stats.
// Uses threshold-based clearing controlled by clearTriggerThreshold +
// retentionWindow defined above.
func (f *gpuTraceFixer) maybeClear() fixerStats {
	f.mu.Lock()
	defer f.mu.Unlock()

	timesLen := len(f.timesAwaitingTraces)
	tracesLen := len(f.tracesAwaitingTimes)

	stats := fixerStats{
		timesLen:  timesLen,
		tracesLen: tracesLen,
	}

	pcLen := len(f.pcTraces)
	pendingLen := len(f.pendingPCSamples)

	if timesLen > clearTriggerThreshold || tracesLen > clearTriggerThreshold ||
		pcLen > clearTriggerThreshold || pendingLen > clearTriggerThreshold {
		nowNs := time.Now().UnixNano()
		// Keep entries within retentionWindow of the max correlation ID.
		// Use signed distance to handle wrap-around correctly.
		for k, evs := range f.timesAwaitingTraces {
			if int32(f.maxCorrelationId-k) > retentionWindow {
				if waitLogEnabled {
					storedAt := f.timesStoredAtNs[k]
					pid := uint32(0)
					if len(evs) > 0 {
						pid = evs[0].Pid
					}
					logWait("time_aw_trace", "evicted", nowNs-storedAt, k, pid,
						fmt.Sprintf("n_times=%d", len(evs)))
				}
				delete(f.timesAwaitingTraces, k)
				delete(f.timesStoredAtNs, k)
			}
		}
		for k, st := range f.tracesAwaitingTimes {
			if int32(f.maxCorrelationId-k) > retentionWindow {
				if waitLogEnabled {
					logWait("trace_aw_time", "evicted", nowNs-st.StoredAtNs, k,
						uint32(st.Meta.PID))
				}
				delete(f.tracesAwaitingTimes, k)
			}
		}
		for k, st := range f.pcTraces {
			if int32(f.maxCorrelationId-k) > retentionWindow {
				if waitLogEnabled {
					logWait("pc_trace", "evicted", nowNs-st.StoredAtNs, k,
						uint32(st.Meta.PID))
				}
				delete(f.pcTraces, k)
			}
		}
		for k, samples := range f.pendingPCSamples {
			if int32(f.maxCorrelationId-k) > retentionWindow {
				stats.pendingSamplesEvicted += len(samples)
				if waitLogEnabled {
					pid := uint32(0)
					if len(samples) > 0 {
						pid = samples[0].ev.Pid
					}
					// Age of the oldest sample in this entry.
					oldest := samples[0].arrivalNs
					for i := range samples {
						if samples[i].arrivalNs < oldest {
							oldest = samples[i].arrivalNs
						}
					}
					logWait("pc_sample", "evicted", nowNs-oldest, k, pid,
						fmt.Sprintf("nsamples=%d", len(samples)))
				}
				delete(f.pendingPCSamples, k)
			}
		}

		stats.timesCleared = timesLen - len(f.timesAwaitingTraces)
		stats.tracesCleared = tracesLen - len(f.tracesAwaitingTimes)
	}

	return stats
}

var (
	cudaDevice          libpf.String
	cudaStream          libpf.String
	cudaGraph           libpf.String
	cudaId              libpf.String
	cudaStallReason     libpf.String
	cudaSassInstruction libpf.String
)

func init() {
	cudaDevice = libpf.Intern("cuda_device")
	cudaStream = libpf.Intern("cuda_stream")
	cudaGraph = libpf.Intern("cuda_graph")
	cudaId = libpf.Intern("cuda_id")
	cudaStallReason = libpf.Intern("cuda_stall_reason")
	cudaSassInstruction = libpf.Intern("cuda_sass_instruction")
}

// nullTerm returns b truncated at the first NUL byte, or all of b if there is
// none. The returned slice aliases b's backing array, so callers that retain
// the result beyond the lifetime of b must copy it (e.g. via string()); callers
// that only use it transiently can avoid the copy with pfunsafe.ToString.
func nullTerm(b []byte) []byte {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return b[:i]
	}
	return b
}

// prepTrace attaches timing information and the demangled kernel name to a symbolized
// CUDA trace, producing a CudaTraceOutput ready for reporting.
func (f *gpuTraceFixer) prepTrace(trace *libpf.Trace, meta *samples.TraceEventMeta,
	cudaFrameIdx int, ev *CuptiKernelEvent) CudaTraceOutput {
	out := CudaTraceOutput{
		Trace: trace,
		Meta:  meta,
	}

	if ev.Graph != 0 {
		// Graphs can have many kernels with same correlation ID.
		// Copy Trace (Frames differ per kernel, Hash differs) and Meta (Value differs)
		// since the original stays in the map for future timing events.
		// CustomLabels are NOT copied: all events for the same correlation ID share
		// identical cuda_device/cuda_stream/cuda_graph values.
		traceCopy := *trace
		traceCopy.Frames = make(libpf.Frames, len(trace.Frames))
		copy(traceCopy.Frames, trace.Frames)
		out.Trace = &traceCopy
		metaCopy := *meta
		out.Meta = &metaCopy
	}

	out.Meta.Value = int64(ev.End - ev.Start)
	if out.Trace.CustomLabels == nil {
		out.Trace.CustomLabels = make(map[libpf.String]libpf.String)
	}

	out.Trace.CustomLabels[cudaDevice] = libpf.Intern(strconv.FormatUint(uint64(ev.Dev), 10))
	if ev.Stream != 0 {
		out.Trace.CustomLabels[cudaStream] = libpf.Intern(strconv.FormatUint(uint64(ev.Stream), 10))
	}
	if ev.Graph != 0 {
		out.Trace.CustomLabels[cudaGraph] = libpf.Intern(strconv.FormatUint(uint64(ev.Graph), 10))
		out.Trace.CustomLabels[cudaId] = libpf.Intern(strconv.FormatUint(uint64(ev.Id), 10))
	}

	// Extract kernel name from timing event and update the CUDA frame.
	// libpf.Intern copies, so sharing ev's backing array via ToString is safe.
	nameBytes := nullTerm(ev.KernelName[:])
	if len(nameBytes) > 0 {
		funcName := libpf.Intern(pfunsafe.ToString(nameBytes))
		out.Trace.Frames[cudaFrameIdx] = unique.Make(libpf.Frame{
			Type:         out.Trace.Frames[cudaFrameIdx].Value().Type,
			FunctionName: funcName,
		})
	}

	return out
}

// InterceptTrace finds the CUDA frame, extracts the correlation ID and CBID,
// and delegates to the appropriate fixer. Returns any traces that are now
// complete — graph launches, or single launches whose timing already arrived.
// Traces awaiting timing are retained inside the fixer and emitted later via
// AddTimes. The caller is responsible for hashing and reporting each output.
func InterceptTrace(trace *libpf.Trace, meta *samples.TraceEventMeta) []CudaTraceOutput {
	// Find the CUDA kernel frame and extract correlation ID + CBID.
	cudaFrameIdx := -1
	var correlationID uint32
	var cbid int32
	for i, uniqueFrame := range trace.Frames {
		if uniqueFrame.Value().Type == libpf.CUDAKernelFrame {
			cudaFrameIdx = i
			packed := uint64(uniqueFrame.Value().AddressOrLineno)
			correlationID = uint32(packed)
			cbid = int32(packed >> 32)
			break
		}
	}
	if cudaFrameIdx < 0 {
		log.Errorf("[cuda] CUDA trace has no CUDAKernelFrame")
		return nil
	}

	log.Debugf("[cuda] adding trace with id %d cbid %d (0x%x) for pid %d",
		correlationID, int(cbid), uint32(cbid), meta.PID)

	pid := meta.PID
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d in InterceptTrace", pid)
		return nil
	}
	fixer := value.(*gpuTraceFixer)

	if isGraphLaunch(cbid) {
		return fixer.addGraphTrace(trace, meta, cudaFrameIdx, correlationID, cbid)
	}
	if out, ok := fixer.addSingleTrace(trace, meta, cudaFrameIdx, correlationID, cbid); ok {
		return []CudaTraceOutput{out}
	}
	return nil
}

// addTimeSingle is a static function that delegates to the appropriate fixer for the PID.
func addTimeSingle(ev *CuptiKernelEvent) (CudaTraceOutput, bool) {
	pid := libpf.PID(ev.Pid)
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d in AddTime", pid)
		return CudaTraceOutput{}, false
	}
	fixer := value.(*gpuTraceFixer)
	fixer.mu.Lock()
	defer fixer.mu.Unlock()
	return fixer.addTime(ev)
}

// AddTimes processes a batch of timing events, taking the lock once per PID.
// Returns all completed traces.
func AddTimes(events []CuptiKernelEvent) []CudaTraceOutput {
	if len(events) == 0 {
		return nil
	}

	var outputs []CudaTraceOutput

	// Fast path: assume all events from same PID (common case)
	pid := libpf.PID(events[0].Pid)
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d in AddTimes", pid)
		return nil
	}
	fixer := value.(*gpuTraceFixer)

	var otherPID []CuptiKernelEvent
	fixer.mu.Lock()
	for i := range events {
		ev := &events[i]
		if libpf.PID(ev.Pid) != pid {
			otherPID = append(otherPID, *ev)
			continue
		}
		if out, ok := fixer.addTime(ev); ok {
			outputs = append(outputs, out)
		}
	}
	fixer.mu.Unlock()

	// Handle rare events from other PIDs
	for i := range otherPID {
		if out, ok := addTimeSingle(&otherPID[i]); ok {
			outputs = append(outputs, out)
		}
	}

	return outputs
}

// MaybeClearAll periodically clears all fixers and returns metrics for the caller to report.
func MaybeClearAll() []metrics.Metric {
	var totalTimes, totalTraces, totalTimesCleared, totalTracesCleared int
	var totalPendingEvicted int

	gpuFixers.Range(func(key, value any) bool {
		fixer := value.(*gpuTraceFixer)
		stats := fixer.maybeClear()
		totalTimes += stats.timesLen
		totalTraces += stats.tracesLen
		totalTimesCleared += stats.timesCleared
		totalTracesCleared += stats.tracesCleared
		totalPendingEvicted += stats.pendingSamplesEvicted

		return true
	})

	out := []metrics.Metric{
		{ID: metrics.IDCudaTimesAwaitingTraces, Value: metrics.MetricValue(totalTimes)},
		{ID: metrics.IDCudaTracesAwaitingTimes, Value: metrics.MetricValue(totalTraces)},
	}
	if totalTimesCleared > 0 || totalTracesCleared > 0 {
		out = append(out,
			metrics.Metric{ID: metrics.IDCudaTimesCleared, Value: metrics.MetricValue(totalTimesCleared)},
			metrics.Metric{ID: metrics.IDCudaTracesCleared, Value: metrics.MetricValue(totalTracesCleared)},
		)
	}
	if totalPendingEvicted > 0 {
		out = append(out,
			metrics.Metric{ID: metrics.IDCudaPendingPCSamplesEvicted, Value: metrics.MetricValue(totalPendingEvicted)},
		)
	}
	return out
}

// Symbolize is a stub - CUDA frames are handled directly by convertFrame,
// so this should never be called in normal operation.
func (i *Instance) Symbolize(f libpf.EbpfFrame, _ *libpf.Frames, _ libpf.FrameMapping) error {
	return fmt.Errorf("CUDA Symbolize called unexpectedly for frame type %d: %w",
		f.Type(), interpreter.ErrMismatchInterpreterType)
}

func (d *data) Unload(_ interpreter.EbpfHandler) {
	for key, le := range d.links {
		log.Debugf("[cuda] parcagpu USDT probes closed for %s (dev=%d ino=%d)",
			d.path, key.DeviceID, key.InodeNum)
		if err := le.link.Unload(); err != nil {
			log.Errorf("error closing cuda usdt link: %s", err)
		}
	}
	d.links = nil
}
