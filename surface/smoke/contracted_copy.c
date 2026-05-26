/* Fixed-contract example. The function `bounded_copy` is unsafe in isolation
   (no length check), but its callers in the (hypothetical) reachable slice
   only ever pass `len <= cap`. We encode that as a hand-written precondition
   in the harness — this is what "fixed contract" means in Phase 1.3 before
   Phase 3.1's LLM-synthesized ACSL. Stage B must prove safe under that
   contract. The contract itself appears in the proof-cache key (Phase 1.4) so
   a cache hit is only valid when the assumed contract still holds. */
#include <stdint.h>
#include <string.h>

void bounded_copy(unsigned char *dst, const unsigned char *src, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

#ifdef CBMC_HARNESS
extern void __CPROVER_assume(int);

#define CAP 32

int main(void) {
    unsigned char dst[CAP];
    unsigned char src[CAP];
    unsigned int len;
    /* Fixed precondition (the "contract"): len is bounded by the buffer cap.
       Phase 1.4 will hash this assumption as part of the proof-cache key. */
    __CPROVER_assume(len <= CAP);
    bounded_copy(dst, src, len);
    return 0;
}
#endif
