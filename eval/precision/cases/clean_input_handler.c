/* Phase 2.5 precision corpus — clean Tier-1 libFuzzer harness.
 *
 * No memory bug: bytes are copied into a fixed-size buffer with strict
 * bounds. ASan must NOT report a crash, so the router should escalate
 * Tier-1 → Tier-2 (no spec) → ... → inconclusive (negative case).
 */
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char buf[64];
    size_t n = size < sizeof(buf) ? size : sizeof(buf);
    for (size_t i = 0; i < n; i++) buf[i] = data[i];
    /* sink so the compiler keeps the copy */
    volatile unsigned char sink = 0;
    for (size_t i = 0; i < n; i++) sink ^= buf[i];
    (void)sink;
    return 0;
}
