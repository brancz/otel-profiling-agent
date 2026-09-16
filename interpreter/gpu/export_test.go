// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import "go.opentelemetry.io/ebpf-profiler/libpf"

// RegisterTestFixer creates and registers a gpuTraceFixer for the given PID,
// skipping the BPF probe attachment that the real Attach path performs.
// For use in tests only.
func RegisterTestFixer(pid libpf.PID) {
	gpuFixers.Store(pid, newGpuTraceFixer(false))
}

// UnregisterTestFixer removes the fixer for the given PID.
func UnregisterTestFixer(pid libpf.PID) {
	gpuFixers.Delete(pid)
}
