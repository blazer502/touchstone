/* Tier-3 BMC smoke: loop exceeds the chosen unwind bound.
 *
 * At --unwind=4 with --unwinding-assertions ON, CBMC must report
 * "unwinding assertion ... : FAILURE" and the driver must return
 * verdict=inconclusive (never silently "safe").
 */
#include <stdint.h>

int main(void) {
    unsigned int n;
    __CPROVER_assume(n > 100 && n < 200);
    unsigned int s = 0;
    for (unsigned int i = 0; i < n; i++) {
        s += i;
    }
    __CPROVER_assert(s >= 0, "trivial");
    return 0;
}
