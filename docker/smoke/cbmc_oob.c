/* CBMC smoke test: 5-element array with an out-of-bounds write CBMC must catch. */
#include <assert.h>
int main(void) {
    int a[5];
    int i;
    __CPROVER_assume(i >= 0 && i < 10);
    a[i] = 42;
    return 0;
}
