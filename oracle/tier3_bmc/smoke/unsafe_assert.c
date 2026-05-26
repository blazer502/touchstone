/* Tier-3 BMC smoke: hypothesis = "writing buf[i] with i == N is OOB".
 *
 * The harness encodes the property as an explicit assertion so the cex
 * trace pins the failing input variable, exercising the Tier-3 PoV
 * extraction path.
 */
#include <stdint.h>

#define N 8

static int buf[N];

void write_at(unsigned int i, int v) {
    /* Bug: off-by-one — allows i == N. */
    if (i <= N) {
        buf[i] = v;
    }
}

int main(void) {
    unsigned int i;   /* nondet */
    int v;            /* nondet */
    __CPROVER_assume(i <= N);
    write_at(i, v);
    /* Property: every accepted i is in-bounds. The off-by-one breaks this. */
    __CPROVER_assert(i < N, "i must be strictly less than N");
    return 0;
}
