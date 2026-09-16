package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"strconv"
	"time"
	"unique"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"

	sasstable "github.com/gnurizen/sass-table"
)

// Comes from cupti_bpf.h from parcagpu
const maxStallReasons = 64

// HandlePCSample processes a single PC sample event. It correlates the sample
// with a CPU trace (if correlation ID is available), decodes the instruction
// mnemonic from the cubin's SASS code, and reports one gpupc trace per
// non-zero stall reason.
func HandlePCSample(ev *CuptiPCSampleEvent, rep reporter.TraceReporter) {
	if _, ok := LoadCubin(ev.Data.CubinCRC); !ok {
		log.Debugf("[cuda] pc sample: cubin 0x%x not in cache, dropping", ev.Data.CubinCRC)
		return
	}

	// Correlate with a CPU trace. If the correlation trace hasn't arrived yet,
	// stash this sample; it is emitted later via emitPCSample when the trace
	// shows up.
	var cpuTrace *SymbolizedCudaTrace
	if ev.CorrelationID != 0 {
		cpuTrace = LookupTraceForPCSample(libpf.PID(ev.Pid), ev.CorrelationID)
		if cpuTrace == nil {
			StorePendingPCSample(libpf.PID(ev.Pid), *ev, rep)
			return
		}
		if waitLogEnabled && cpuTrace.StoredAtNs != 0 {
			logWait("pc_sample", "matched_immediate",
				time.Now().UnixNano()-cpuTrace.StoredAtNs,
				ev.CorrelationID, ev.Pid)
		}
	}

	emitPCSample(ev, rep, cpuTrace)
}

// buildGpuPCTrace constructs a trace for one GPU PC sample: a single
// CUDAPCFrame carrying the function-relative offset, optionally followed by the
// CPU frames from the correlated trace.
//
// The GPU frame's mapping build ID is the cubin CRC (one mapping per cubin) and
// the kernel's mangled name rides on it as the system name (in FunctionName),
// so the backend resolves it per function to (kernel, file, line).
func buildGpuPCTrace(cpuTrace *SymbolizedCudaTrace, cubinMapping libpf.FrameMapping,
	kernelName string, pcOffset uint64) *libpf.Trace {

	// Count CPU frames (exclude the original CUDAKernelFrame).
	cpuFrameCount := 0
	if cpuTrace != nil {
		cpuFrameCount = len(cpuTrace.Trace.Frames) - 1
		if cpuFrameCount < 0 {
			cpuFrameCount = 0
		}
	}

	trace := &libpf.Trace{
		Frames: make(libpf.Frames, 0, 1+cpuFrameCount),
	}

	trace.Frames = append(trace.Frames, unique.Make(libpf.Frame{
		Type:            libpf.CUDAPCFrame,
		FunctionName:    libpf.Intern(kernelName),
		AddressOrLineno: libpf.AddressOrLineno(pcOffset),
		Mapping:         cubinMapping,
	}))

	// CPU frames from the correlated trace (skip its CUDAKernelFrame).
	if cpuTrace != nil {
		for i, f := range cpuTrace.Trace.Frames {
			if i == cpuTrace.CUDAFrameIdx {
				continue
			}
			trace.Frames = append(trace.Frames, f)
		}
	}

	return trace
}

// gpuPCLabels builds the per-sample custom labels for a GPU PC sample: the CUPTI
// stall reason, the device the sample's context is bound to (when the attached
// parcagpu build's probe reports one), and, when decoded, the SASS instruction
// mnemonic at the offset.
func gpuPCLabels(stallName libpf.String, mnemonic string, deviceID uint32,
	hasDevice bool) map[libpf.String]libpf.String {
	labels := map[libpf.String]libpf.String{
		cudaStallReason: stallName,
	}
	if hasDevice {
		labels[cudaDevice] = libpf.Intern(strconv.FormatUint(uint64(deviceID), 10))
	}
	if mnemonic != "" {
		labels[cudaSassInstruction] = libpf.Intern(mnemonic)
	}
	return labels
}

// buildGpuPCMeta constructs TraceEventMeta for a gpupc sample.
// If a CPU trace is available, metadata is copied from it.
//
// Value carries the raw PC sample count for this (pid, trace). The reporter
// pairs it with the per-pid GpuConfig (via LoadGpuConfig) to set the profile
// period to ns_per_sample, so a "count" sample_type stays mathematically
// convertible to GPU nanoseconds via value × period.
func buildGpuPCMeta(cpuTrace *SymbolizedCudaTrace, pid uint32,
	sampleCount int64) *samples.TraceEventMeta {
	meta := &samples.TraceEventMeta{
		Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
		PID:       libpf.PID(pid),
		Origin:    support.TraceOriginGpuPC,
		Value:     sampleCount,
	}
	if cpuTrace != nil && cpuTrace.Meta != nil {
		meta.Timestamp = cpuTrace.Meta.Timestamp
		meta.Comm = cpuTrace.Meta.Comm
		meta.ProcessName = cpuTrace.Meta.ProcessName
		meta.ExecutablePath = cpuTrace.Meta.ExecutablePath
		meta.ContainerID = cpuTrace.Meta.ContainerID
		meta.TID = cpuTrace.Meta.TID
		meta.CPU = cpuTrace.Meta.CPU
		meta.APMServiceName = cpuTrace.Meta.APMServiceName
		meta.EnvVars = cpuTrace.Meta.EnvVars
	}
	return meta
}

// decodeInstruction decodes the SASS mnemonic of the instruction at pcOffset in
// the cubin. CUPTI reports pcOffset relative to the start of functionName, and
// ptxas emits one ".text.<mangled-name>" section per function starting at the
// function base, so when functionName names such a section we can index it
// directly — an exact, layout-independent lookup.
//
// If the name doesn't resolve (empty name, or an unconventional cubin layout
// where functions share a .text section), we fall back to guessing: first
// treating pcOffset as a section-absolute address, then as a function-relative
// offset into each section.
func decodeInstruction(info *CubinInfo, functionName string, pcOffset uint64) string {
	if info.SMVersion == 0 || len(info.Texts) == 0 {
		return ""
	}

	// Deterministic path: decode at pcOffset within the function's own section.
	if functionName != "" {
		want := ".text." + functionName
		for _, ts := range info.Texts {
			if ts.Name != want {
				continue
			}
			if pcOffset+16 > uint64(len(ts.Data)) {
				break // right section, but offset is out of range; fall back
			}
			// Authoritative: this is the function's section, so return whatever
			// it decodes to rather than guessing against other sections.
			return sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[pcOffset:])
		}
	}

	// Fallback: pcOffset as a section-absolute address.
	for _, ts := range info.Texts {
		if pcOffset >= ts.Addr && pcOffset < ts.Addr+uint64(len(ts.Data)) {
			off := pcOffset - ts.Addr
			if off+16 <= uint64(len(ts.Data)) {
				if m := sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[off:]); m != "" {
					return m
				}
			}
		}
	}

	// Fallback: pcOffset as a function-relative offset into each section.
	for _, ts := range info.Texts {
		if pcOffset+16 <= uint64(len(ts.Data)) {
			if m := sasstable.DecodeMnemonicFromSlice(info.SMVersion, ts.Data[pcOffset:]); m != "" {
				return m
			}
		}
	}

	return ""
}
