/* Tier-2 angr smoke (unsat case).
 *
 * Target dead_target() has its address NOT taken and is never called from main.
 * angr should drain to deadended without ever scheduling it.
 */
#include <unistd.h>

__attribute__((noinline, used)) void dead_target(void) {
    volatile int x = 7;
    (void)x;
    _exit(13);
}

int main(void) {
    char buf[4];
    (void)read(0, buf, 4);
    _exit(0);
}
