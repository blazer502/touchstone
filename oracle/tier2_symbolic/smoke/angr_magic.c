/* Tier-2 angr smoke (sat case).
 *
 * Reads 4 bytes from stdin; if they equal "ABCD", reaches win().
 * angr should resolve stdin to "ABCD" deterministically.
 */
#include <unistd.h>

__attribute__((noinline)) void win(void) {
    /* target — angr looks for a state at this address */
    volatile int x = 42;
    (void)x;
    _exit(0);
}

__attribute__((noinline)) void lose(void) {
    volatile int y = 0;
    (void)y;
    _exit(1);
}

int main(void) {
    char buf[4];
    if (read(0, buf, 4) != 4) return 2;
    if (buf[0] == 'A' && buf[1] == 'B' && buf[2] == 'C' && buf[3] == 'D') {
        win();
    } else {
        lose();
    }
    return 0;
}
