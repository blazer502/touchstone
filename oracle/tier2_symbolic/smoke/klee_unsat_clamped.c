/* Tier-2 KLEE smoke (unsat case).
 *
 * Encodes: "after clamp(x, 0, 9), reading buf[clamped] is always in bounds".
 * KLEE explores all symbolic values of x, finds no OOB / assert failure.
 * Verdict should be "unsat" (under the encoded property + environment model).
 */
#include <klee/klee.h>

static int clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

int main(void) {
    int x;
    klee_make_symbolic(&x, sizeof(x), "x");
    int buf[10] = {0};
    int i = clamp(x, 0, 9);
    /* This dereference is provably safe under the clamp. */
    klee_assert(i >= 0 && i < 10);
    return buf[i];
}
