/* Tier-3 BMC harness for hypothesis: off_by_one_oob */
#include <stdint.h>

static int buf[8];
void write_at(unsigned int i, int v){ if (i<=8) buf[i]=v; }

int main(void) {
    unsigned int i;  /* nondet */
    int v;  /* nondet */
    __CPROVER_assume(i <= 8);
    write_at(i, v);
    __CPROVER_assert(i < 8, "index must be strictly less than 8");
    return 0;
}
