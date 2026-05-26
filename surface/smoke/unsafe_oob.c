/* Unsafe: i is bounded only by N+1, so write of a[N] is OOB. Stage B must
   produce a counterexample (verdict=unsafe). */
#include <stdint.h>

#define N 16

void off_by_one(int *a, unsigned int i, int v) {
    if (i <= N) {       /* off-by-one: allows i == N */
        a[i] = v;
    }
}

#ifdef CBMC_HARNESS
int main(void) {
    int a[N] = {0};
    unsigned int i;
    int v;
    off_by_one(a, i, v);
    return 0;
}
#endif
