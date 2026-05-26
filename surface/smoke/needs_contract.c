/* Phase 3.1 demo: in isolation the function is unsafe (no length check), but
   under the precondition `len <= CAP` it is safe. The Stage-B refinement loop
   should: (1) run CBMC with no contract, get an OOB cex with `len > CAP`;
   (2) ask the synthesizer for a precondition; (3) re-run CBMC under that
   precondition and obtain `safe`. */
#include <stdint.h>

#define CAP 16

void write_at(unsigned char *buf, unsigned int i, unsigned char v) {
    buf[i] = v;
}

#ifdef CBMC_HARNESS
extern void __CPROVER_assume(int);

int main(void) {
    unsigned char buf[CAP];
    unsigned int i;
    unsigned char v;
    /* @CONTRACTS */
    /* No precondition above the marker — the refinement loop must synthesize
       `i <= CAP-1` (or `i < CAP`) before CBMC can prove safe. */
    write_at(buf, i, v);
    return 0;
}
#endif
