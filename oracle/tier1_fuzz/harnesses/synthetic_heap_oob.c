/* Hand-written libFuzzer harness — deterministic heap-buffer-overflow.
 *
 * Purpose: Tier-1 driver validation only. The bug fires for any input whose
 * size > 16: we malloc(16) and write to buf[size-1]. libFuzzer's coverage
 * feedback grows the corpus through the size-gated branches in seconds.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Ladder of size-gated branches so libFuzzer's coverage feedback escalates
     * input size in steps — keeps the trigger reproducible without trace-cmp. */
    if (size < 1)  return 0;
    if (size < 4)  return 0;
    if (size < 8)  return 0;
    if (size < 12) return 0;
    if (size < 17) return 0;
    char *buf = (char *)malloc(16);
    if (!buf) return 0;
    /* Write 1 byte past end of 16-byte heap chunk: ASan reports heap-buffer-overflow. */
    buf[size - 1] = (char)data[0];
    free(buf);
    return 0;
}
