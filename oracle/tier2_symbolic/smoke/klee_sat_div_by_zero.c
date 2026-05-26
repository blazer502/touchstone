/* Tier-2 KLEE smoke (sat case).
 *
 * Encodes: "for some symbolic int x, the program triggers a division-by-zero
 * at the marked location". KLEE finds the model x=0 deterministically and
 * emits test*.ktest + test*.div.err.
 */
#include <klee/klee.h>

int divide(int n, int d) {
    return n / d;            /* KLEE: division by zero when d == 0 */
}

int main(void) {
    int d;
    klee_make_symbolic(&d, sizeof(d), "d");
    int n = 7;
    return divide(n, d);
}
