#include <arm_neon.h>
#include <stdint.h>

__attribute__((noinline))
void c_sha256_four_rounds(
    uint32x4_t *state0_pointer,
    uint32x4_t *state1_pointer,
    const uint32x4_t *work_pointer) {
  uint32x4_t state0 = *state0_pointer;
  uint32x4_t state1 = *state1_pointer;
  const uint32x4_t work = *work_pointer;
  const uint32x4_t previous_state0 = state0;
  state0 = vsha256hq_u32(state0, state1, work);
  state1 = vsha256h2q_u32(state1, previous_state0, work);
  *state0_pointer = state0;
  *state1_pointer = state1;
}
