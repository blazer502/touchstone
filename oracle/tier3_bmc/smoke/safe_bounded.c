/* Tier-3 BMC smoke: safe under a verified precondition.
 *
 * The harness clamps `i` inside [0, N) before the indexed write, so CBMC
 * with --bounds-check should prove safe at any unwind >= 1.
 *
 * Uninitialized locals are nondet under CBMC, which is the canonical idiom
 * for symbolic inputs in a BMC harness.
 */
#include <stdint.h>

#define N 8

int clamp_write(int *a, unsigned int i, int v) {
    if (i < N) {
        a[i] = v;
        return 1;
    }
    return 0;
}

int main(void) {
    int a[N] = {0};
    unsigned int i;
    int v;
    (void)clamp_write(a, i, v);
    return 0;
}
