/*
 * Positive-control harness for Phase 4.3 (mirrors Phase-4.2's k2 control).
 *
 * Drives SQLite (linked, exercised) but the *crash* comes from a deterministic
 * stack-buffer-overflow at the harness layer when the input starts with the
 * marker "OOB!" — the surrounding sqlite3_open()/close() guarantees the
 * library is actually loaded and called, so a green run here means the live
 * toolchain (clang-14 + ASan + libsqlite3 link) is fully wired.
 *
 * Verdict semantics under the agent loop:
 *   crash on "OOB!\x00…" input  ⇒  paired-positive-control fired (toolchain OK)
 *   any other input             ⇒  no crash; ASan stays silent
 */
#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

__attribute__((noinline))
static void smash(const uint8_t *src, size_t n) {
    char buf[16];
    /* Deliberate stack-OOB; ASan should diagnose immediately. */
    for (size_t i = 0; i < n; i++) buf[i] = (char)src[i];
    /* Force the write to be observable. */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_open(":memory:", &db);
    if (db) sqlite3_close(db);

    if (size >= 4 && memcmp(data, "OOB!", 4) == 0) {
        smash(data, size); /* writes `size` bytes into 16-byte buf */
    }
    return 0;
}
