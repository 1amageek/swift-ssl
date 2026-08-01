#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct allocation_probe_counters {
  _Atomic uint64_t malloc_calls;
  _Atomic uint64_t malloc_bytes;
  _Atomic uint64_t calloc_calls;
  _Atomic uint64_t calloc_bytes;
  _Atomic uint64_t realloc_calls;
  _Atomic uint64_t realloc_bytes;
  _Atomic uint64_t aligned_calls;
  _Atomic uint64_t aligned_bytes;
  _Atomic uint64_t free_calls;
  _Atomic uint64_t memcpy_calls;
  _Atomic uint64_t memcpy_bytes;
  _Atomic uint64_t memmove_calls;
  _Atomic uint64_t memmove_bytes;
};

static _Atomic bool allocation_probe_enabled = false;
static struct allocation_probe_counters allocation_probe_counters;

// Interposition boundary invariants:
// - dyld redirects calls from other images; calls made by this image continue
//   to the original libSystem implementation and therefore do not recurse.
// - Counters contain no pointers and use relaxed atomics after the acquire/release
//   measurement toggle, so concurrent allocator calls remain data-race safe.
// - The probe never retains, dereferences, binds, or changes ownership of caller
//   memory. Requested byte counts saturate instead of overflowing.
// - The benchmark process owns the loaded image and unloads it only at process exit.

static uint64_t requested_product(size_t count, size_t size) {
  if (size != 0 && count > UINT64_MAX / size) {
    return UINT64_MAX;
  }
  return (uint64_t)count * (uint64_t)size;
}

static void reset_counter(_Atomic uint64_t *counter) {
  atomic_store_explicit(counter, 0, memory_order_relaxed);
}

static void add_counter(_Atomic uint64_t *counter, uint64_t value) {
  uint64_t current = atomic_load_explicit(counter, memory_order_relaxed);
  while (true) {
    uint64_t next = value > UINT64_MAX - current ? UINT64_MAX : current + value;
    if (atomic_compare_exchange_weak_explicit(
            counter,
            &current,
            next,
            memory_order_relaxed,
            memory_order_relaxed)) {
      return;
    }
  }
}

static uint64_t load_counter(_Atomic uint64_t *counter) {
  return atomic_load_explicit(counter, memory_order_relaxed);
}

void swift_ssl_allocation_probe_start(void) {
  reset_counter(&allocation_probe_counters.malloc_calls);
  reset_counter(&allocation_probe_counters.malloc_bytes);
  reset_counter(&allocation_probe_counters.calloc_calls);
  reset_counter(&allocation_probe_counters.calloc_bytes);
  reset_counter(&allocation_probe_counters.realloc_calls);
  reset_counter(&allocation_probe_counters.realloc_bytes);
  reset_counter(&allocation_probe_counters.aligned_calls);
  reset_counter(&allocation_probe_counters.aligned_bytes);
  reset_counter(&allocation_probe_counters.free_calls);
  reset_counter(&allocation_probe_counters.memcpy_calls);
  reset_counter(&allocation_probe_counters.memcpy_bytes);
  reset_counter(&allocation_probe_counters.memmove_calls);
  reset_counter(&allocation_probe_counters.memmove_bytes);
  atomic_store_explicit(&allocation_probe_enabled, true, memory_order_release);
}

void swift_ssl_allocation_probe_stop_and_print(void) {
  atomic_store_explicit(&allocation_probe_enabled, false, memory_order_release);
  printf(
      "ALLOCATION_RESULT,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,"
      "%llu,%llu,%llu,%llu\n",
      load_counter(&allocation_probe_counters.malloc_calls),
      load_counter(&allocation_probe_counters.malloc_bytes),
      load_counter(&allocation_probe_counters.calloc_calls),
      load_counter(&allocation_probe_counters.calloc_bytes),
      load_counter(&allocation_probe_counters.realloc_calls),
      load_counter(&allocation_probe_counters.realloc_bytes),
      load_counter(&allocation_probe_counters.aligned_calls),
      load_counter(&allocation_probe_counters.aligned_bytes),
      load_counter(&allocation_probe_counters.free_calls),
      load_counter(&allocation_probe_counters.memcpy_calls),
      load_counter(&allocation_probe_counters.memcpy_bytes),
      load_counter(&allocation_probe_counters.memmove_calls),
      load_counter(&allocation_probe_counters.memmove_bytes));
}

static bool allocation_probe_is_enabled(void) {
  return atomic_load_explicit(&allocation_probe_enabled, memory_order_acquire);
}

static void *swift_ssl_probe_malloc(size_t size) {
  void *result = malloc(size);
  if (allocation_probe_is_enabled()) {
    add_counter(&allocation_probe_counters.malloc_calls, 1);
    add_counter(&allocation_probe_counters.malloc_bytes, size);
  }
  return result;
}

static void *swift_ssl_probe_calloc(size_t count, size_t size) {
  void *result = calloc(count, size);
  if (allocation_probe_is_enabled()) {
    add_counter(&allocation_probe_counters.calloc_calls, 1);
    add_counter(
        &allocation_probe_counters.calloc_bytes,
        requested_product(count, size));
  }
  return result;
}

static void *swift_ssl_probe_realloc(void *pointer, size_t size) {
  void *result = realloc(pointer, size);
  if (allocation_probe_is_enabled()) {
    add_counter(&allocation_probe_counters.realloc_calls, 1);
    add_counter(&allocation_probe_counters.realloc_bytes, size);
  }
  return result;
}

static int swift_ssl_probe_posix_memalign(
    void **pointer,
    size_t alignment,
    size_t size) {
  int result = posix_memalign(pointer, alignment, size);
  if (result == 0 && allocation_probe_is_enabled()) {
    add_counter(&allocation_probe_counters.aligned_calls, 1);
    add_counter(&allocation_probe_counters.aligned_bytes, size);
  }
  return result;
}

static void *swift_ssl_probe_aligned_alloc(size_t alignment, size_t size) {
  void *result = aligned_alloc(alignment, size);
  if (result != NULL && allocation_probe_is_enabled()) {
    add_counter(&allocation_probe_counters.aligned_calls, 1);
    add_counter(&allocation_probe_counters.aligned_bytes, size);
  }
  return result;
}

static void swift_ssl_probe_free(void *pointer) {
  bool counted = pointer != NULL && allocation_probe_is_enabled();
  free(pointer);
  if (counted) {
    add_counter(&allocation_probe_counters.free_calls, 1);
  }
}

static void *swift_ssl_probe_memcpy(void *destination, const void *source, size_t size) {
  void *result = memcpy(destination, source, size);
  if (allocation_probe_is_enabled()) {
    add_counter(&allocation_probe_counters.memcpy_calls, 1);
    add_counter(&allocation_probe_counters.memcpy_bytes, size);
  }
  return result;
}

static void *swift_ssl_probe_memmove(void *destination, const void *source, size_t size) {
  void *result = memmove(destination, source, size);
  if (allocation_probe_is_enabled()) {
    add_counter(&allocation_probe_counters.memmove_calls, 1);
    add_counter(&allocation_probe_counters.memmove_bytes, size);
  }
  return result;
}

#define DYLD_INTERPOSE(replacement, replacee)                                  \
  __attribute__((used)) static struct {                                        \
    const void *replacement;                                                   \
    const void *replacee;                                                      \
  } _interpose_##replacee __attribute__((section("__DATA,__interpose"))) = {   \
      (const void *)(uintptr_t)&replacement,                                   \
      (const void *)(uintptr_t)&replacee,                                      \
  }

DYLD_INTERPOSE(swift_ssl_probe_malloc, malloc);
DYLD_INTERPOSE(swift_ssl_probe_calloc, calloc);
DYLD_INTERPOSE(swift_ssl_probe_realloc, realloc);
DYLD_INTERPOSE(swift_ssl_probe_posix_memalign, posix_memalign);
DYLD_INTERPOSE(swift_ssl_probe_aligned_alloc, aligned_alloc);
DYLD_INTERPOSE(swift_ssl_probe_free, free);
DYLD_INTERPOSE(swift_ssl_probe_memcpy, memcpy);
DYLD_INTERPOSE(swift_ssl_probe_memmove, memmove);
