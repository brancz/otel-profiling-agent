/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"bytes"
	"context"
	"path"
	"time"

	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/ipc"
	"github.com/apache/arrow/go/v16/arrow/memory"
	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/hostmetadata/host"
	profilestore "github.com/elastic/otel-profiling-agent/proto/experiments/parca/profilestore/v1alpha1"

	"github.com/elastic/otel-profiling-agent/debug/log"
	"github.com/elastic/otel-profiling-agent/libpf"

	lru "github.com/elastic/go-freelru"
	"github.com/zeebo/xxh3"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*ParcaReporter)(nil)

// traceInfo holds static information about a trace.
type traceInfo struct {
	files          []libpf.FileID
	linenos        []libpf.AddressOrLineno
	frameTypes     []libpf.FrameType
	comm           string
	podName        string
	podNamespace   string
	containerName  string
	apmServiceName string
}

// sample holds dynamic information about traces.
type sample struct {
	// In most cases OTEP/profiles requests timestamps in a uint64 format
	// and use nanosecond precision - https://github.com/open-telemetry/oteps/issues/253
	timestamps []uint64
	count      uint32
}

// execInfo enriches an executable with additional metadata.
type execInfo struct {
	fileName string
	buildID  string
}

// sourceInfo allows to map a frame to its source origin.
type sourceInfo struct {
	lineNumber     libpf.SourceLineno
	functionOffset uint32
	functionName   string
	filePath       string
}

// funcInfo is a helper to construct profile.Function messages.
type funcInfo struct {
	name     string
	fileName string
}

// ParcaReporter receives and transforms information to be OTLP/profiles compliant.
type ParcaReporter struct {
	// client for the connection to the receiver.
	client profilestore.ProfileStoreServiceClient

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// rpcStats stores gRPC related statistics.
	rpcStats *statsHandlerImpl

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long term storage information that might
	// be duplicated in other places but not accessible for ParcaReporter.

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// traces stores static information needed for samples.
	traces *lru.SyncedLRU[libpf.TraceHash, traceInfo]

	// samples holds a map of currently encountered traces.
	samples *lru.SyncedLRU[libpf.TraceHash, sample]

	// fallbackSymbols keeps track of FrameID to their symbol.
	fallbackSymbols *lru.SyncedLRU[libpf.FrameID, string]

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, map[libpf.AddressOrLineno]sourceInfo]
}

// hashString is a helper function for LRUs that use string as a key.
// xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

// ReportFramesForTrace accepts a trace with the corresponding frames
// and caches this information.
func (r *ParcaReporter) ReportFramesForTrace(trace *libpf.Trace) {
	if v, exists := r.traces.Peek(trace.Hash); exists {
		// As traces is filled from two different API endpoints,
		// some information for the trace might be available already.
		// For simplicty, the just received information overwrites the
		// the existing one.
		v.files = trace.Files
		v.linenos = trace.Linenos
		v.frameTypes = trace.FrameTypes

		r.traces.Add(trace.Hash, v)
	} else {
		r.traces.Add(trace.Hash, traceInfo{
			files:      trace.Files,
			linenos:    trace.Linenos,
			frameTypes: trace.FrameTypes,
		})
	}
}

// ReportCountForTrace accepts a hash of a trace with a corresponding count and
// caches this information.
func (r *ParcaReporter) ReportCountForTrace(traceHash libpf.TraceHash, timestamp libpf.UnixTime32,
	count uint16, comm, podName, podNamespace, containerName string) {
	if v, exists := r.traces.Peek(traceHash); exists {
		// As traces is filled from two different API endpoints,
		// some information for the trace might be available already.
		// For simplicty, the just received information overwrites the
		// the existing one.
		v.comm = comm
		v.podName = podName
		v.podNamespace = podNamespace
		v.containerName = containerName

		r.traces.Add(traceHash, v)
	} else {
		r.traces.Add(traceHash, traceInfo{
			comm:          comm,
			podName:       podName,
			podNamespace:  podNamespace,
			containerName: containerName,
		})
	}

	if v, ok := r.samples.Peek(traceHash); ok {
		v.count += uint32(count)
		v.timestamps = append(v.timestamps, uint64(timestamp))

		r.samples.Add(traceHash, v)
	} else {
		r.samples.Add(traceHash, sample{
			count:      uint32(count),
			timestamps: []uint64{uint64(timestamp)},
		})
	}
}

// ReportFallbackSymbol enqueues a fallback symbol for reporting, for a given frame.
func (r *ParcaReporter) ReportFallbackSymbol(frameID libpf.FrameID, symbol string) {
	if _, exists := r.fallbackSymbols.Peek(frameID); exists {
		return
	}
	r.fallbackSymbols.Add(frameID, symbol)
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *ParcaReporter) ExecutableMetadata(_ context.Context,
	fileID libpf.FileID, fileName, buildID string) {
	baseName := path.Base(fileName)
	if baseName == "/" {
		// There are circumstances where there is no filename.
		// E.g. kernel module 'bpfilter_umh' before Linux 5.9-rc1 uses
		// fork_usermode_blob() and launches process with a blob without
		// filename mapped in as the executable.
		baseName = "<anonymous-blob>"
	}

	r.executables.Add(fileID, execInfo{
		fileName: baseName,
		buildID:  buildID,
	})
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *ParcaReporter) FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno,
	lineNumber libpf.SourceLineno, functionOffset uint32, functionName, filePath string) {
	if v, exists := r.frames.Get(fileID); exists {
		if filePath == "" {
			// The new filePath may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := v[addressOrLine]; exists {
				filePath = s.filePath
			}
		}
		v[addressOrLine] = sourceInfo{
			lineNumber:     lineNumber,
			functionOffset: functionOffset,
			functionName:   functionName,
			filePath:       filePath,
		}
		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     lineNumber,
		functionOffset: functionOffset,
		functionName:   functionName,
		filePath:       filePath,
	}
	r.frames.Add(fileID, v)
}

// ReportHostMetadata enqueues host metadata.
func (r *ParcaReporter) ReportHostMetadata(metadataMap map[string]string) {
	r.addHostmetadata(metadataMap)
}

// ReportHostMetadataBlocking enqueues host metadata.
func (r *ParcaReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	r.addHostmetadata(metadataMap)
	return nil
}

// addHostmetadata adds to and overwrites host metadata.
func (r *ParcaReporter) addHostmetadata(metadataMap map[string]string) {
	for k, v := range metadataMap {
		r.hostmetadata.Add(k, v)
	}
}

// ReportMetrics is a NOP for ParcaReporter.
func (r *ParcaReporter) ReportMetrics(_ uint32, _ []uint32, _ []int64) {}

// Stop triggers a graceful shutdown of ParcaReporter.
func (r *ParcaReporter) Stop() {
	close(r.stopSignal)
}

// GetMetrics returns internal metrics of ParcaReporter.
func (r *ParcaReporter) GetMetrics() Metrics {
	return Metrics{
		RPCBytesOutCount:  r.rpcStats.getRPCBytesOut(),
		RPCBytesInCount:   r.rpcStats.getRPCBytesIn(),
		WireBytesOutCount: r.rpcStats.getWireBytesOut(),
		WireBytesInCount:  r.rpcStats.getWireBytesIn(),
	}
}

// StartOTLP sets up and manages the reporting connection to a OTLP backend.
func StartOTLP(mainCtx context.Context, c *Config) (Reporter, error) {
	cacheSize := config.TraceCacheEntries()

	traces, err := lru.NewSynced[libpf.TraceHash, traceInfo](cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	samples, err := lru.NewSynced[libpf.TraceHash, sample](cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	fallbackSymbols, err := lru.NewSynced[libpf.FrameID, string](cacheSize, libpf.FrameID.Hash32)
	if err != nil {
		return nil, err
	}

	executables, err := lru.NewSynced[libpf.FileID, execInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		map[libpf.AddressOrLineno]sourceInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	// Next step: Dynamically configure the size of this LRU.
	// Currently we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, err
	}

	r := &ParcaReporter{
		stopSignal:      make(chan libpf.Void),
		client:          nil,
		rpcStats:        newStatsHandler(),
		traces:          traces,
		samples:         samples,
		fallbackSymbols: fallbackSymbols,
		executables:     executables,
		frames:          frames,
		hostmetadata:    hostmetadata,
	}

	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	// Establish the gRPC connection before going on, waiting for a response
	// from the collectionAgent endpoint.
	// Use grpc.WithBlock() in setupGrpcConnection() for this to work.
	otlpGrpcConn, err := waitGrpcEndpoint(ctx, c, r.rpcStats)
	if err != nil {
		cancelReporting()
		close(r.stopSignal)
		return nil, err
	}
	r.client = profilestore.NewProfileStoreServiceClient(otlpGrpcConn)

	go func() {
		tick := time.NewTicker(c.Times.ReportInterval())

		// This is intentionally not initialized, as we want the first report
		// to be based on the first collection timestamp. This may be imprecise
		// if there is not much happening on the CPU in normal operation, but
		// inverse if we initialized this with time.Now() we run the risk of
		// including a lot more data that has accumulated since before starting
		// this loop and overreporting data in the first report.
		var previous time.Time

		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.reportProfile(ctx, previous, time.Now()); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(c.Times.ReportInterval(), 0.2))
			}
		}
	}()

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	// - close the gRPC connection with collection-agent
	go func() {
		<-r.stopSignal
		cancelReporting()
		if err := otlpGrpcConn.Close(); err != nil {
			log.Fatalf("Stopping connection of OTLP client client failed: %v", err)
		}
	}()

	return r, nil
}

// reportOTLPProfile creates and sends out an OTLP profile.
func (r *ParcaReporter) reportProfile(ctx context.Context, previous, now time.Time) error {
	record := r.getProfile(ctx, previous, now)
	defer record.Release()

	if record.NumRows() == 0 {
		log.Debugf("Skip sending of profile with no samples")
		return nil
	}

	var buf bytes.Buffer
	w := ipc.NewWriter(&buf,
		ipc.WithSchema(record.Schema()),
		ipc.WithAllocator(memory.DefaultAllocator),
	)
	defer w.Close()

	if err := w.Write(record); err != nil {
		return err
	}

	_, err := r.client.Write(ctx, &profilestore.WriteRequest{
		Record: buf.Bytes(),
	})
	return err
}

func (r *ParcaReporter) getHostname() string {
	v, _ := r.hostmetadata.Get(host.KeyHostname)
	return v
}

func (r *ParcaReporter) newWriter() Writer {
	standardLabels := []string{"comm"}
	kubernetesLabels := []string{"pod", "namespace", "container"}
	hostnameLabels := []string{"hostname"}

	labels := append(standardLabels, kubernetesLabels...)
	labels = append(labels, hostnameLabels...)
	w := NewV1Writer(memory.DefaultAllocator, labels)

	return w
}

func (r *ParcaReporter) writeCommonLabels(w Writer, rows uint64) {
	hostnameLabels := w.LabelBuildersMap["hostname"]
	hostname := r.getHostname()

	hostnameLabels.ree.Append(rows)
	hostnameLabels.bd.AppendString(hostname)
}

// getProfile returns an OTLP profile containing all collected samples up to this moment.
func (r *ParcaReporter) getProfile(ctx context.Context, previous, now time.Time) arrow.Record {
	// Avoid overlapping locks by copying its content.
	sampleKeys := r.samples.Keys()
	samplesCpy := make(map[libpf.TraceHash]sample, len(sampleKeys))
	for _, k := range sampleKeys {
		v, ok := r.samples.Get(k)
		if !ok {
			continue
		}
		samplesCpy[k] = v
		r.samples.Remove(k)
	}

	var samplesWoTraceinfo []libpf.TraceHash

	for trace := range samplesCpy {
		if _, exists := r.traces.Peek(trace); !exists {
			samplesWoTraceinfo = append(samplesWoTraceinfo, trace)
		}
	}

	if len(samplesWoTraceinfo) != 0 {
		log.Debugf("Missing trace information for %d samples", len(samplesWoTraceinfo))
		// Return samples for which relevant information is not available yet.
		for _, trace := range samplesWoTraceinfo {
			r.samples.Add(trace, samplesCpy[trace])
			delete(samplesCpy, trace)
		}
	}

	w := r.newWriter()
	defer w.Release()

	commLabels := w.LabelBuildersMap["comm"]
	podLabels := w.LabelBuildersMap["pod"]
	namespaceLabels := w.LabelBuildersMap["namespace"]
	containerLabels := w.LabelBuildersMap["container"]

	startTS, endTS := uint64(0), uint64(0)
	for traceHash, sampleInfo := range samplesCpy {
		// Earlier we peeked into traces for traceHash and know it exists.
		trace, _ := r.traces.Get(traceHash)

		for _, ts := range sampleInfo.timestamps {
			if ts < startTS || startTS == 0 {
				startTS = ts
				continue
			}
			if ts > endTS {
				endTS = ts
			}
		}

		// Walk every frame of the trace.
		if len(trace.frameTypes) == 0 {
			w.LocationsList.Append(false)
		} else {
			w.LocationsList.Append(true)
		}
		for i := range trace.frameTypes {
			w.Locations.Append(true)
			w.Address.Append(uint64(trace.linenos[i]))
			w.FrameType.AppendString(trace.frameTypes[i].String())

			switch frameKind := trace.frameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				execInfo, exists := r.executables.Get(trace.files[i])

				// Next step: Select a proper default value,
				// if the name of the executable is not known yet.
				var fileName = "UNKNOWN"
				if exists {
					fileName = execInfo.fileName
				}

				w.MappingStart.Append(uint64(0))
				w.MappingLimit.Append(uint64(0))
				w.MappingOffset.Append(uint64(trace.linenos[i]))
				w.MappingFile.AppendString(fileName)
				w.MappingBuildID.AppendString(execInfo.buildID)
				w.Lines.Append(false)
			case libpf.KernelFrame:
				w.MappingStart.Append(uint64(0))
				w.MappingLimit.Append(uint64(0))
				w.MappingOffset.Append(uint64(0))
				w.MappingFile.AppendString("[kernel.kallsyms]")
				w.MappingBuildID.AppendString("")

				// Reconstruct frameID
				frameID := libpf.NewFrameID(trace.files[i], trace.linenos[i])

				symbol, exists := r.fallbackSymbols.Get(frameID)
				if !exists {
					// TODO: choose a proper default value if the kernel symbol was not
					// reported yet.
					symbol = "UNKNOWN"
				}

				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(int64(0))
				w.FunctionName.AppendString(symbol)
				w.FunctionSystemName.AppendString("")
				w.FunctionFilename.AppendString("vmlinux")
				w.FunctionStartLine.Append(int64(0))
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
				w.MappingStart.Append(uint64(0))
				w.MappingLimit.Append(uint64(0))
				w.MappingOffset.Append(uint64(0))
				w.MappingFile.AppendString("agent-internal-error-frame")
				w.MappingBuildID.AppendString("")
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(int64(0))
				w.FunctionName.AppendString("aborted")
				w.FunctionSystemName.AppendString("")
				w.FunctionFilename.AppendString("")
				w.FunctionStartLine.Append(int64(0))
			default:
				var (
					lineNumber   int64
					functionName string
					filePath     string
				)

				fileIDInfo, exists := r.frames.Get(trace.files[i])
				if !exists {
					// At this point, we do not have enough information for the
					// frame. Therefore, we report a dummy entry and use the
					// interpreter as filename.
					functionName = "UNRESOLVED"
					filePath = "UNRESOLVED"
				} else {
					si, exists := fileIDInfo[trace.linenos[i]]
					if !exists {
						// At this point, we do not have enough information for
						// the frame. Therefore, we report a dummy entry and
						// use the interpreter as filename. To differentiate
						// this case with the case where no information about
						// the file ID is available at all, we use a different
						// name for reported function.
						functionName = "UNRESOLVED"
						filePath = "UNRESOLVED"
					} else {
						lineNumber = int64(si.lineNumber)
						functionName = si.functionName
						filePath = si.filePath
					}
				}
				w.MappingStart.Append(uint64(0))
				w.MappingLimit.Append(uint64(0))
				w.MappingOffset.Append(uint64(0))
				w.MappingFile.AppendString(frameKind.String())
				w.MappingBuildID.AppendString("")
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(lineNumber)
				w.FunctionName.AppendString(functionName)
				w.FunctionSystemName.AppendString("")
				w.FunctionFilename.AppendString(filePath)
				w.FunctionStartLine.Append(int64(0))
			}
		}

		commLabels.AppendString(trace.comm)
		podLabels.AppendString(trace.podName)
		namespaceLabels.AppendString(trace.podNamespace)
		containerLabels.AppendString(trace.containerName)
		w.Value.Append(int64(sampleInfo.count))
	}

	var (
		ts, duration int64
	)
	if previous.IsZero() {
		// start and end ts are in milliseconds but we need nanoseconds.
		startNanos := time.Unix(int64(startTS), 0).UnixNano()
		endNanos := time.Unix(int64(endTS), 0).UnixNano()

		duration = endNanos - startNanos
		ts = startNanos / 1e6
	} else {
		duration = now.UnixNano() - previous.UnixNano()
		ts = now.UnixMilli()
	}

	rows := uint64(w.Value.Len())

	r.writeCommonLabels(w, rows)
	w.Producer.ree.Append(rows)
	w.Producer.bd.AppendString("parca_agent")
	w.SampleType.ree.Append(rows)
	w.SampleType.bd.AppendString("samples")
	w.SampleUnit.ree.Append(rows)
	w.SampleUnit.bd.AppendString("count")
	w.PeriodType.ree.Append(rows)
	w.PeriodType.bd.AppendString("cpu")
	w.PeriodUnit.ree.Append(rows)
	w.PeriodUnit.bd.AppendString("nanoseconds")
	w.Temporality.ree.Append(rows)
	w.Temporality.bd.AppendString("delta")
	w.Period.ree.Append(rows)
	// Since the period is of type cpu nanoseconds it is the time between
	// samples.
	w.Period.ib.Append(1e9 / int64(config.SamplesPerSecond()))
	w.Timestamp.ree.Append(rows)
	w.Timestamp.ib.Append(ts)
	w.Duration.ree.Append(rows)
	w.Duration.ib.Append(duration)

	return w.NewRecord()
}
