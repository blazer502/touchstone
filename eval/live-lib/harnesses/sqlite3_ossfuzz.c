/*
 * Live-target libFuzzer harness for SQLite 3.37 (Phase 4.3).
 *
 * Mirrors the public OSS-Fuzz sqlite3 fuzzer shape: open an in-memory DB,
 * execute the fuzzer input as SQL, close. Heavy work paths (PRAGMA,
 * recursive CTEs, JSON1) are exposed by routing input through sqlite3_exec
 * against an in-memory DB; this is the same surface OSS-Fuzz exercises.
 *
 * Built with ASan + libFuzzer via Phase-2.1 Tier-1 driver
 * (oracle.tier1_fuzz.userspace.build_libfuzzer). Links against the host
 * libsqlite3 (3.37.2) shared library — that is the "latest" SQLite already
 * on disk per docs/toolchain.lock host pins.
 *
 * Soundness: the harness has no host-effect calls (matches the Phase-3.2
 * banned-call rule); SQL string is bounded to fuzzer input size (capped at
 * 1 MiB by libFuzzer's default).
 */
#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > (1u << 20)) return 0;

    /* SQL needs a NUL-terminated buffer. */
    char *sql = (char *)malloc(size + 1);
    if (!sql) return 0;
    memcpy(sql, data, size);
    sql[size] = '\0';

    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) == SQLITE_OK && db) {
        /* Bound the work per input so the fuzzer keeps moving. */
        sqlite3_limit(db, SQLITE_LIMIT_LENGTH,        1 << 16);
        sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH,    1 << 16);
        sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 16);
        sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP,       25000);
        sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH,    100);

        char *err = NULL;
        sqlite3_exec(db, sql, NULL, NULL, &err);
        if (err) sqlite3_free(err);
    }
    if (db) sqlite3_close(db);
    free(sql);
    return 0;
}
