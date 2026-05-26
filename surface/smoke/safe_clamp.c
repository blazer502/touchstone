/* Safe: index is clamped before write. Stage B must prove no OOB. */
#include <stdint.h>

#define N 16

void clamp_write(int *a, unsigned int i, int v) {
    if (i < N) {
        a[i] = v;
    }
}

#ifdef CBMC_HARNESS
extern void __CPROVER_assume(int);
int main(void) {
    int a[N] = {0};
    unsigned int i;
    int v;
    clamp_write(a, i, v);
    return 0;
}
#endif
