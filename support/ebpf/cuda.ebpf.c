#include "bpfdefs.h"
#include "types.h"
// cupti_bpf.h uses u32/u64 from types.h, so it must be included after it.
#include "cupti_bpf.h"
#include "tracemgmt.h"
#include "usdt_args.h"

// cuda_correlation reads the correlation ID from the USDT probe and records a trace.
SEC("usdt/parcagpu/cuda_correlation")
int BPF_USDT(cuda_correlation, u32 correlation_id, s32 cbid)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  DEBUG_PRINT("cuda_correlation_probe: correlation_id=%u, cbid=%u", correlation_id, cbid);

  u64 ts      = bpf_ktime_get_ns();
  // Cast cbid to s32 first to get sign extension, then to u64
  u64 cuda_id = correlation_id + ((u64)cbid << 32);
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cuda_id);
}

// Event type discriminator at offset 0 of every event submitted to cupti_events.
// Each event type has its own struct; the Go consumer peeks the first 4 bytes
// and dispatches accordingly.
#define EVENT_TYPE_KERNEL           1
#define EVENT_TYPE_CUBIN_LOADED     2
#define EVENT_TYPE_PC_SAMPLE        3
#define EVENT_TYPE_STALL_REASON_MAP 4
#define EVENT_TYPE_ERROR            5
#define EVENT_TYPE_GPU_CONFIG       6

#define MAX_KERNEL_NAME_LEN   256
#define MAX_FUNC_NAME_LEN     128
#define MAX_ERROR_MSG_LEN     256
#define MAX_ERROR_COMP_LEN    64
#define STALL_REASON_NAME_LEN 64

struct kernel_event {
  u32 event_type; // = EVENT_TYPE_KERNEL
  u32 pid;
  u64 start;
  u64 end;
  u64 graph_node_id;
  u32 correlation_id;
  u32 device_id;
  u32 stream_id;
  u32 graph_id;
  char kernel_name[MAX_KERNEL_NAME_LEN];
};

struct cubin_event {
  u32 event_type; // = EVENT_TYPE_CUBIN_LOADED
  u32 pid;
  u64 cubin_crc;
  u64 cubin_ptr; // user-space address (Go reads bytes via /proc/pid/mem)
  u64 cubin_size;
};

// gpu_config_event reports the parcagpu sampling factor + GPU clock so the
// agent can convert PC sample counts to nanoseconds. Fired once per CUPTI
// context-init and replayed on USDT semaphore-count increase.
struct gpu_config_event {
  u32 event_type; // = EVENT_TYPE_GPU_CONFIG
  u32 pid;
  u32 device_id;
  u32 sampling_factor;
  u32 clock_khz;
  u32 sm_count;
};

// CUDA 12.4+ extends cupti_pc_data with a trailing correlationId (u32) at
// offset CUPTI_PC_DATA_BASE_SIZE.  We require 12.4+ for pc sampling.
#define CUPTI_PC_DATA_V22_SIZE (CUPTI_PC_DATA_BASE_SIZE + 4)

// pc_sample_event embeds cupti_pc_data + correlation_id so cuda_pc_sample_batch
// can read the producer's 60-byte record directly into the ringbuf-reserved
// event with a single bpf_probe_read_user — no stack-local intermediate, no
// field-by-field copy.  cupti_pc_data is packed but all its fields are already
// naturally aligned, so the layout matches a plain Go struct with the same
// fields.
//
// The data.size, data._pc_pad, data.function_name_ptr, data.stall_reason_ptr
// fields are unused by the Go consumer but ride along.  data.function_index is
// surfaced for logging/correlation only.
struct pc_sample_event {
  u32 event_type; // = EVENT_TYPE_PC_SAMPLE
  u32 pid;
  struct cupti_pc_data data; // 56 bytes (packed but naturally aligned)
  u32 correlation_id;        // CUDA 12.4+ extension, follows immediately
  // Device the collecting CUcontext is bound to (fixed for its lifetime).
  // Was 8-byte alignment padding; repurposed since the size/alignment match.
  u32 device_id;
  char function_name[MAX_FUNC_NAME_LEN];
  struct cupti_stall_reason stall_reasons[MAX_STALL_REASONS];
};

struct stall_reason_map_event {
  u32 event_type; // = EVENT_TYPE_STALL_REASON_MAP
  u32 count;
  u32 pid;
  u32 _pad;
  char names[MAX_STALL_REASONS][STALL_REASON_NAME_LEN];
};

struct error_event {
  u32 event_type; // = EVENT_TYPE_ERROR
  s32 code;
  u32 pid;
  u32 _pad;
  char message[MAX_ERROR_MSG_LEN];
  char component[MAX_ERROR_COMP_LEN];
};

// Per-CPU scratch space for large structs that exceed the BPF 512-byte stack
// limit (cupti_activity_kernel5 = 160 B; stall_reason_map_event ≈ 4 KB).
// Also stashes pre-parsed USDT args for the activity_batch and pc_sample_batch
// tail calls — bpf_get_attach_cookie does not return the correct cookie after
// bpf_tail_call, so we parse args in cuda_probe and pass them via this map.
#define PTR_BATCH 16

struct cuda_scratch {
  struct cupti_activity_kernel5 rec;
  u64 ab_ptrs_base;
  u32 ab_num_activities;
  u32 ab_next_offset; // start of the next activity chunk to process; 0 on entry
  u64 pc_ptrs_base;
  u32 pc_count;
  u32 pc_next_offset; // start of the next pc-sample chunk to process; 0 on entry
  u32 pc_device_id;
};

struct cuda_scratch_heap_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct cuda_scratch);
  __uint(max_entries, 1);
} cuda_scratch_heap SEC(".maps");

// Per-chunk limit for activity_batch.  Like the pc_sample limits below, we
// chunk across up to BPF_AB_MAX_TAIL_CALLS bpf_tail_call hops so each
// program's verifier complexity stays well under the 1M-insn cap on older
// kernels — on 5.15 the single-shot 128-record body is close enough to the
// threshold that a clang/inlining version bump alone can tip it over.
#define BPF_AB_BATCH_LIMIT    64
#define BPF_AB_MAX_TAIL_CALLS 2
#define BPF_AB_TOTAL_LIMIT    (BPF_AB_BATCH_LIMIT * BPF_AB_MAX_TAIL_CALLS)

// Per-chunk limit for pc_sample_batch.  Verified independently per program;
// BPF_PC_BATCH_LIMIT is what the verifier walks in a single load.  Using
// MAX_PC_BATCH_SIZE (512) directly blows past the 1M-insn complexity cap on
// older kernels (e.g. 6.1) because each iteration has stall-reason +
// function-name reads.  We chain up to BPF_PC_MAX_TAIL_CALLS chunks via
// bpf_tail_call to handle batches up to BPF_PC_TOTAL_LIMIT records.
#define BPF_PC_BATCH_LIMIT    128
#define BPF_PC_MAX_TAIL_CALLS 8
#define BPF_PC_TOTAL_LIMIT    (BPF_PC_BATCH_LIMIT * BPF_PC_MAX_TAIL_CALLS)

// Tail-call prog array for cuda_probe and the pc_sample_batch chunk chain.
// Heavy loop bodies (activity_batch, pc_sample_batch) push the inlined
// dispatcher past BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192), so they live in
// dedicated tail-called programs.  pc_sample_batch additionally tail-chains
// into itself (slot 1) up to BPF_PC_MAX_TAIL_CALLS times to process batches
// larger than BPF_PC_BATCH_LIMIT records.
//
// Key 0: cuda_activity_batch_tail
// Key 1: cuda_pc_sample_batch_tail
struct cuda_progs_t {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 2);
} cuda_progs SEC(".maps");

// Unified ringbuf for all CUPTI events sent to user-space. Every event begins
// with a u32 event_type discriminator at offset 0. 1 MB base capacity here is a
// fallback; userspace resizes it at load via CUPTIEventScaleFactor (see
// tracer.go), since graph-heavy GPU workloads overflow 1 MB and drop events.
struct cupti_events_t {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
} cupti_events SEC(".maps");

// Per-(pid, crc) dedup for cubin_loaded USDT fires. The parcagpu library
// re-emits every loaded cubin whenever the USDT semaphore refcount
// increases (a tracer joins) and on a periodic refresh, so an attached
// agent sees the same (pid, crc) repeatedly across a workload's
// lifetime. Without dedup each duplicate would drive a /proc/<pid>/mem
// read of up to 256 MB on the Go side. LRU eviction caps the map size
// and lets re-fires through again if an entry ages out.
struct cubin_seen_key {
  u64 crc;
  u32 pid;
  u32 _pad;
};
struct cubin_seen_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct cubin_seen_key);
  __type(value, u8);
  __uint(max_entries, 1 << 14);
} cubin_seen SEC(".maps");

// Per-(pid, dev) dedup for gpu_config USDT fires. Same flooding concern as
// cubin_seen but the payload is tiny — dedup still keeps the ringbuf clean.
struct gpu_config_seen_key {
  u32 pid;
  u32 device_id;
};
struct gpu_config_seen_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct gpu_config_seen_key);
  __type(value, u8);
  __uint(max_entries, 256);
} gpu_config_seen SEC(".maps");

SEC("usdt/parcagpu/cuda_kernel")
int BPF_USDT(
  cuda_kernel_exec,
  u64 start,
  u64 end,
  u32 correlation_id,
  u32 device_id,
  u32 stream_id,
  u32 graph_id,
  u64 graph_node_id,
  u64 name_ptr)
{
  u64 pid_tgid     = bpf_get_current_pid_tgid();
  u32 pid          = pid_tgid >> 32;
  const char *name = (const char *)name_ptr;

  struct kernel_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    increment_metric(metricID_CUPTIEventsRingbufFull);
    return 0;
  }
  evt->event_type     = EVENT_TYPE_KERNEL;
  evt->pid            = pid;
  evt->correlation_id = correlation_id;
  evt->start          = start;
  evt->end            = end;
  evt->graph_node_id  = graph_node_id;
  evt->device_id      = device_id;
  evt->stream_id      = stream_id;
  evt->graph_id       = graph_id;

  int chars = bpf_probe_read_user_str((char *)&evt->kernel_name, sizeof(evt->kernel_name), name);
  if (chars <= 0) {
    evt->kernel_name[0] = 'e';
    evt->kernel_name[1] = 'r';
    evt->kernel_name[2] = 'r';
    evt->kernel_name[3] = '\0';
  }

  DEBUG_PRINT("cuda_kernel_exec: pid=%u corr_id=%u dev=%u", pid, correlation_id, device_id);

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// process_activity_chunk handles a single chunk of up to BPF_AB_BATCH_LIMIT
// activity records at [start_offset, end) within ptrs_base[0..num_activities).
// After the chunk, if more records remain, it stashes the continuation state
// in scratch and tail-calls cuda_progs[0] (== cuda_activity_batch_tail).  Up
// to BPF_AB_MAX_TAIL_CALLS hops cover BPF_AB_TOTAL_LIMIT records; each
// program is verified independently so the per-program complexity stays well
// below the 1M-insn cap on older kernels.
static EBPF_INLINE int
process_activity_chunk(struct pt_regs *ctx, u64 ptrs_base, u32 num_activities, u32 start_offset)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  struct cupti_activity_kernel5 *rec = &scratch->rec;

  u32 end = num_activities;
  if (end > start_offset + BPF_AB_BATCH_LIMIT) {
    end = start_offset + BPF_AB_BATCH_LIMIT;
  }

  // Stack-local pointer batch — small enough for the BPF stack.
  u64 ptrs[PTR_BATCH] = {};

  // Nested loop: outer reads PTR_BATCH pointers at a time, inner processes
  // each.  Keeps the verifier's jump-sequence count well under
  // BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192).
  for (u32 batch = 0; batch < BPF_AB_BATCH_LIMIT / PTR_BATCH; batch++) {
    u32 base = start_offset + batch * PTR_BATCH;
    if (base >= end) {
      break;
    }

    if (bpf_probe_read_user(ptrs, sizeof(ptrs), (void *)(ptrs_base + base * sizeof(u64))) != 0) {
      break;
    }

    for (u32 j = 0; j < PTR_BATCH; j++) {
      if (base + j >= end) {
        break;
      }

      u64 rec_ptr = ptrs[j];

      // Read the full activity record and filter by kind.
      if (bpf_probe_read_user(rec, sizeof(*rec), (void *)rec_ptr) != 0) {
        continue;
      }
      if (
        rec->kind != CUPTI_ACTIVITY_KIND_KERNEL &&
        rec->kind != CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) {
        continue;
      }

      struct kernel_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
      if (!evt) {
        increment_metric(metricID_CUPTIEventsRingbufFull);
        continue;
      }
      evt->event_type     = EVENT_TYPE_KERNEL;
      evt->pid            = pid;
      evt->correlation_id = rec->correlation_id;
      evt->start          = rec->start;
      evt->end            = rec->end;
      evt->graph_node_id  = rec->graph_node_id;
      evt->device_id      = rec->device_id;
      evt->stream_id      = rec->stream_id;
      evt->graph_id       = rec->graph_id;

      const char *name = (const char *)rec->name_ptr;
      int chars =
        bpf_probe_read_user_str((char *)&evt->kernel_name, sizeof(evt->kernel_name), name);
      if (chars <= 0) {
        evt->kernel_name[0] = 'e';
        evt->kernel_name[1] = 'r';
        evt->kernel_name[2] = 'r';
        evt->kernel_name[3] = '\0';
      }

      DEBUG_PRINT(
        "cuda_activity_batch: corr_id=%u kind=%u dev=%u",
        rec->correlation_id,
        rec->kind,
        rec->device_id);

      bpf_ringbuf_submit(evt, 0);
    }
  }

  // Chain to next chunk if more records remain.  bpf_tail_call replaces the
  // current program; if it returns, it failed (max recursion or empty slot).
  if (end < num_activities) {
    scratch->ab_ptrs_base      = ptrs_base;
    scratch->ab_num_activities = num_activities;
    scratch->ab_next_offset    = end;
    bpf_tail_call(ctx, &cuda_progs, 0);
    DEBUG_PRINT("cuda_activity_batch: tail_call failed at offset=%u", end);
  }
  return 0;
}

// USDT: parcagpu/activity_batch(const void **ptrs, uint32 num_activities).
// Entry point for single-shot uprobe attachment.  Processes the first chunk
// and tail-chains to cuda_activity_batch_tail for any remaining chunks.
SEC("usdt/parcagpu/activity_batch")
int BPF_USDT(cuda_activity_batch, u64 ptrs_base, u32 num_activities)
{
  DEBUG_PRINT("cuda_activity_batch: num=%u ptrs_base=0x%llx", num_activities, ptrs_base);
  if (num_activities > BPF_AB_TOTAL_LIMIT) {
    num_activities = BPF_AB_TOTAL_LIMIT;
  }
  return process_activity_chunk(ctx, ptrs_base, num_activities, 0);
}

// Tail-call entry point for the activity_batch chunk chain.  Reads
// continuation state from scratch and processes the next chunk.  Re-entered
// up to BPF_AB_MAX_TAIL_CALLS times via bpf_tail_call from
// process_activity_chunk.
SEC("usdt/cuda_activity_batch_tail")
int cuda_activity_batch_tail(struct pt_regs *ctx)
{
  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  return process_activity_chunk(
    ctx, scratch->ab_ptrs_base, scratch->ab_num_activities, scratch->ab_next_offset);
}

// USDT: parcagpu/cubin_loaded(uint64 crc, const char *cubin, uint64 size).
// Emits a single cubin_event so the Go side can pull bytes via /proc/pid/mem.
// Deduped per (pid, crc) via cubin_seen — the lib re-fires every loaded cubin
// on every CUPTI callback, which would otherwise flood user-space.
SEC("usdt/parcagpu/cubin_loaded")
int BPF_USDT(cuda_cubin_loaded, u64 cubin_crc, u64 cubin_ptr, u64 cubin_size)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  struct cubin_seen_key key = {
    .crc  = cubin_crc,
    .pid  = pid,
    ._pad = 0,
  };
  if (bpf_map_lookup_elem(&cubin_seen, &key)) {
    return 0;
  }

  struct cubin_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    increment_metric(metricID_CUPTIEventsRingbufFull);
    // Ringbuf full — don't mark seen so a later re-fire gets another shot.
    return 0;
  }
  evt->event_type = EVENT_TYPE_CUBIN_LOADED;
  evt->pid        = pid;
  evt->cubin_crc  = cubin_crc;
  evt->cubin_ptr  = cubin_ptr;
  evt->cubin_size = cubin_size;
  bpf_ringbuf_submit(evt, 0);

  u8 one = 1;
  bpf_map_update_elem(&cubin_seen, &key, &one, BPF_ANY);

  DEBUG_PRINT("cuda_cubin_loaded: pid=%u crc=0x%llx size=%llu", pid, cubin_crc, cubin_size);
  return 0;
}

// USDT: parcagpu/gpu_config(uint32 deviceId, uint32 samplingFactor,
//                            uint32 clockKHz, uint32 smCount).
// Static per-context config; deduped per (pid, dev) so the parcagpu emit-
// metadata replay loop doesn't flood the ringbuf.
SEC("usdt/parcagpu/gpu_config")
int BPF_USDT(cuda_gpu_config, u32 device_id, u32 sampling_factor, u32 clock_khz, u32 sm_count)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  struct gpu_config_seen_key key = {
    .pid       = pid,
    .device_id = device_id,
  };
  if (bpf_map_lookup_elem(&gpu_config_seen, &key)) {
    return 0;
  }

  struct gpu_config_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    increment_metric(metricID_CUPTIEventsRingbufFull);
    return 0;
  }
  evt->event_type      = EVENT_TYPE_GPU_CONFIG;
  evt->pid             = pid;
  evt->device_id       = device_id;
  evt->sampling_factor = sampling_factor;
  evt->clock_khz       = clock_khz;
  evt->sm_count        = sm_count;
  bpf_ringbuf_submit(evt, 0);

  u8 one = 1;
  bpf_map_update_elem(&gpu_config_seen, &key, &one, BPF_ANY);

  DEBUG_PRINT("cuda_gpu_config: pid=%u dev=%u clock_khz=%u", pid, device_id, clock_khz);
  return 0;
}

// USDT: parcagpu/stall_reason_map(const char *names, uint32 count).
// Emits a single stall_reason_map_event with all names blob-copied.
// The event is too big for the BPF stack (~4 KB) so we reserve directly into
// the ringbuf and read user memory through that pointer.
SEC("usdt/parcagpu/stall_reason_map")
int BPF_USDT(cuda_stall_reason_map, u64 names_base, u32 count)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  if (count > MAX_STALL_REASONS) {
    count = MAX_STALL_REASONS;
  }

  struct stall_reason_map_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    increment_metric(metricID_CUPTIEventsRingbufFull);
    return 0;
  }
  evt->event_type = EVENT_TYPE_STALL_REASON_MAP;
  evt->count      = count;
  evt->pid        = pid;
  evt->_pad       = 0;

  // Single blob copy of the whole names table.  The producer guarantees the
  // upstream buffer is exactly MAX_STALL_REASONS*STALL_REASON_NAME_LEN bytes
  // and zero-padded.
  if (bpf_probe_read_user(evt->names, sizeof(evt->names), (void *)names_base) != 0) {
    bpf_ringbuf_discard(evt, 0);
    return 0;
  }

  bpf_ringbuf_submit(evt, 0);
  DEBUG_PRINT("cuda_stall_reason_map: pid=%u count=%u", pid, count);
  return 0;
}

// Error codes for the err_exit path of cuda_pc_sample_batch.
#define PC_SAMPLE_ERR_PROBE_READ   1
#define PC_SAMPLE_ERR_RINGBUF_FULL 2

// process_pc_sample_chunk handles a single chunk of up to BPF_PC_BATCH_LIMIT
// records starting at start_offset within ptrs_base[0..count).  After the
// chunk, if more records remain (start_offset + BPF_PC_BATCH_LIMIT < count),
// it stashes the continuation state in scratch and tail-calls into
// cuda_progs[1] (== cuda_pc_sample_batch_tail).  Up to BPF_PC_MAX_TAIL_CALLS
// hops cover BPF_PC_TOTAL_LIMIT records; each program is verified
// independently, so the per-program complexity stays under the 1M-insn cap on
// older kernels.
//
// Error handling: any read or ringbuf failure jumps to err_exit, which bails
// out of the entire batch.  We don't `continue` past per-record errors because
// the BPF verifier on kernels < 6.4 doesn't merge post-continue state cleanly
// with the next iteration's head, blowing past the 1M-insn complexity cap.
// A single termination path is dramatically cheaper to verify.
static EBPF_INLINE int
process_pc_sample_chunk(
  struct pt_regs *ctx, u64 ptrs_base, u32 count, u32 start_offset, u32 device_id)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 err      = 0;

  u32 end = count;
  if (end > start_offset + BPF_PC_BATCH_LIMIT) {
    end = start_offset + BPF_PC_BATCH_LIMIT;
  }

  // Nested loop mirrors cuda_activity_batch — outer reads PTR_BATCH pointers
  // at a time into a stack-local array, inner processes them.
  u64 ptrs[PTR_BATCH];

  for (u32 batch = 0; batch < BPF_PC_BATCH_LIMIT / PTR_BATCH; batch++) {
    u32 base = start_offset + batch * PTR_BATCH;
    if (base >= end) {
      break;
    }

    if (bpf_probe_read_user(ptrs, sizeof(ptrs), (void *)(ptrs_base + base * sizeof(u64))) != 0) {
      err = PC_SAMPLE_ERR_PROBE_READ;
      goto err_exit;
    }

    for (u32 j = 0; j < PTR_BATCH; j++) {
      if (base + j >= end) {
        break;
      }

      u64 rec_ptr = ptrs[j];

      struct pc_sample_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
      if (!evt) {
        increment_metric(metricID_CUPTIEventsRingbufFull);
        err = PC_SAMPLE_ERR_RINGBUF_FULL;
        goto err_exit;
      }

      // Read the 60-byte cupti_pc_data + correlation_id record directly into
      // evt — no stack-local intermediate, no field copies.  The 4 trailing
      // bytes past sizeof(evt->data) (==56) land in evt->correlation_id.
      if (bpf_probe_read_user(&evt->data, CUPTI_PC_DATA_V22_SIZE, (void *)rec_ptr) != 0) {
        bpf_ringbuf_discard(evt, 0);
        err = PC_SAMPLE_ERR_PROBE_READ;
        goto err_exit;
      }

      evt->event_type = EVENT_TYPE_PC_SAMPLE;
      evt->pid        = pid;
      evt->device_id  = device_id;

      // bpf_probe_read_user_str returns -EFAULT on a NULL ptr without zeroing
      // the destination, and ringbuf-reserved memory isn't pre-zeroed.  Pre-
      // write '\0' so the buffer is sane on either path.
      evt->function_name[0] = '\0';
      if (
        bpf_probe_read_user_str(
          evt->function_name, sizeof(evt->function_name), (void *)evt->data.function_name_ptr) <
        0) {
        bpf_ringbuf_discard(evt, 0);
        err = PC_SAMPLE_ERR_PROBE_READ;
        goto err_exit;
      }

      // No clamp on stall_reason_count — the Go consumer already clamps to
      // MAX_STALL_REASONS and the fixed-size copy below caps what's actually
      // readable to MAX_STALL_REASONS entries regardless of the count value.
      if (
        bpf_probe_read_user(
          evt->stall_reasons, sizeof(evt->stall_reasons), (void *)evt->data.stall_reason_ptr) !=
        0) {
        bpf_ringbuf_discard(evt, 0);
        err = PC_SAMPLE_ERR_PROBE_READ;
        goto err_exit;
      }

      bpf_ringbuf_submit(evt, 0);
    }
  }

  // Chain to next chunk if more records remain.  bpf_tail_call replaces the
  // current program; if it returns, it failed (max recursion or empty slot).
  if (end < count) {
    u32 zero                     = 0;
    struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
    if (!scratch) {
      return 0;
    }
    scratch->pc_ptrs_base   = ptrs_base;
    scratch->pc_count       = count;
    scratch->pc_next_offset = end;
    scratch->pc_device_id   = device_id;
    bpf_tail_call(ctx, &cuda_progs, 1);
    DEBUG_PRINT("cuda_pc_sample_batch: tail_call failed at offset=%u", end);
  }
  return 0;

err_exit:
  DEBUG_PRINT("cuda_pc_sample_batch: bailing out, err=%u offset=%u", err, start_offset);
  return 0;
}

// USDT: parcagpu/pc_sample_batch(const void **ptrs, uint32 count, uint32 deviceId).
// Entry point for single-shot uprobe attachment.  Processes the first chunk
// and tail-chains to cuda_pc_sample_batch_tail for any remaining chunks.
SEC("usdt/parcagpu/pc_sample_batch")
int BPF_USDT(cuda_pc_sample_batch, u64 ptrs_base, u32 count, u32 device_id)
{
  if (count > BPF_PC_TOTAL_LIMIT) {
    count = BPF_PC_TOTAL_LIMIT;
  }
  return process_pc_sample_chunk(ctx, ptrs_base, count, 0, device_id);
}

// Tail-call entry point for the chunk chain.  Reads continuation state from
// scratch and processes the next chunk.  Re-entered up to
// BPF_PC_MAX_TAIL_CALLS times via bpf_tail_call from process_pc_sample_chunk.
SEC("usdt/cuda_pc_sample_batch_tail")
int cuda_pc_sample_batch_tail(struct pt_regs *ctx)
{
  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  return process_pc_sample_chunk(
    ctx, scratch->pc_ptrs_base, scratch->pc_count, scratch->pc_next_offset,
    scratch->pc_device_id);
}

// USDT: parcagpu/error(int32 code, const char *message, const char *component).
SEC("usdt/parcagpu/error")
int BPF_USDT(cuda_error, s32 code, u64 message_ptr, u64 component_ptr)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  struct error_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    increment_metric(metricID_CUPTIEventsRingbufFull);
    return 0;
  }
  evt->event_type   = EVENT_TYPE_ERROR;
  evt->code         = code;
  evt->pid          = pid;
  evt->_pad         = 0;
  evt->message[0]   = '\0';
  evt->component[0] = '\0';
  if (message_ptr) {
    bpf_probe_read_user_str(evt->message, sizeof(evt->message), (void *)message_ptr);
  }
  if (component_ptr) {
    bpf_probe_read_user_str(evt->component, sizeof(evt->component), (void *)component_ptr);
  }
  bpf_ringbuf_submit(evt, 0);

  DEBUG_PRINT("cuda_error: pid=%u code=%d", pid, code);
  return 0;
}

// Cookie values for the cuda_probe multi-probe dispatcher.
// Must match the cookie values set in cuda.go.
#define CUDA_PROG_CORRELATION     0
#define CUDA_PROG_KERNEL_EXEC     1
#define CUDA_PROG_ACTIVITY_BATCH  2
#define CUDA_PROG_CUBIN_LOADED    3
#define CUDA_PROG_PC_SAMPLE_BATCH 4
#define CUDA_PROG_STALL_REASON    5
#define CUDA_PROG_ERROR           6
#define CUDA_PROG_GPU_CONFIG      7

SEC("usdt/cuda_probe")
int cuda_probe(struct pt_regs *ctx)
{
  u64 full_cookie = bpf_get_attach_cookie(ctx);
  u32 cookie      = (u32)(full_cookie & 0xFFFFFFFF);

  switch (cookie) {
  case CUDA_PROG_CORRELATION: return BPF_USDT_CALL(cuda_correlation, correlation_id, cbid);
  case CUDA_PROG_KERNEL_EXEC:
    return BPF_USDT_CALL(
      cuda_kernel_exec,
      start,
      end,
      correlation_id,
      device_id,
      stream_id,
      graph_id,
      graph_node_id,
      name);
  case CUDA_PROG_ACTIVITY_BATCH: {
    // Parse USDT args before the tail call — bpf_get_attach_cookie does not
    // return the correct cookie after bpf_tail_call.
    u32 zero                     = 0;
    struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
    if (!scratch) {
      break;
    }
    u32 num = (u32)bpf_usdt_arg1(ctx);
    if (num > BPF_AB_TOTAL_LIMIT) {
      num = BPF_AB_TOTAL_LIMIT;
    }
    scratch->ab_ptrs_base      = (u64)bpf_usdt_arg0(ctx);
    scratch->ab_num_activities = num;
    scratch->ab_next_offset    = 0;
    bpf_tail_call(ctx, &cuda_progs, 0);
    break;
  }
  case CUDA_PROG_CUBIN_LOADED:
    return BPF_USDT_CALL(cuda_cubin_loaded, cubin_crc, cubin_ptr, cubin_size);
  case CUDA_PROG_PC_SAMPLE_BATCH: {
    u32 zero                     = 0;
    struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
    if (!scratch) {
      break;
    }
    u32 cnt = (u32)bpf_usdt_arg1(ctx);
    if (cnt > BPF_PC_TOTAL_LIMIT) {
      cnt = BPF_PC_TOTAL_LIMIT;
    }
    scratch->pc_ptrs_base   = (u64)bpf_usdt_arg0(ctx);
    scratch->pc_count       = cnt;
    scratch->pc_next_offset = 0;
    scratch->pc_device_id   = (u32)bpf_usdt_arg2(ctx);
    bpf_tail_call(ctx, &cuda_progs, 1);
    break;
  }
  case CUDA_PROG_STALL_REASON: return BPF_USDT_CALL(cuda_stall_reason_map, names_base, count);
  case CUDA_PROG_ERROR: return BPF_USDT_CALL(cuda_error, code, message_ptr, component_ptr);
  case CUDA_PROG_GPU_CONFIG:
    return BPF_USDT_CALL(cuda_gpu_config, device_id, sampling_factor, clock_khz, sm_count);
  default: DEBUG_PRINT("cuda_probe: unknown cookie %u", cookie); break;
  }
  return 0;
}
