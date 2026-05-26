/* Bounded only with --unwind: Without a loop invariant the verdict from a BMC
   is "safe up to N", not unbounded-safe. Used to demonstrate the inconclusive
   verdict path (CBMC reports unwinding-assertion violations beyond bound). */
#include <stdint.h>

unsigned int sum_to(unsigned int n) {
    unsigned int s = 0;
    for (unsigned int i = 0; i < n; i++) {
        s += i;
    }
    return s;
}

#ifdef CBMC_HARNESS
int main(void) {
    unsigned int n;
    sum_to(n);
    return 0;
}
#endif
