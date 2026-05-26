/* Juliet testcasesupport stubs for CBMC verification (Phase 1.5).
 *
 * The Juliet testcases include "std_testcase.h" which pulls system headers and
 * declares helpers (printLine, printIntLine, globalReturnsTrueOrFalse, ...)
 * defined in testcasesupport/io.c. CBMC doesn't need those bodies — we just
 * need symbols so the parse succeeds and any side-effect-free helper is
 * havoc'd safely. The bug being checked lives in the testcase's *_bad()
 * function, not in any helper. Keeping the stubs trivial means CBMC's
 * --pointer-check / --bounds-check / --memory-leak-check see the real flaw.
 */
#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

const int GLOBAL_CONST_TRUE  = 1;
const int GLOBAL_CONST_FALSE = 0;
const int GLOBAL_CONST_FIVE  = 5;
int globalTrue  = 1;
int globalFalse = 0;
int globalFive  = 5;
int globalArgc = 0;
char **globalArgv = 0;

/* printLine actually dereferences its argument — Juliet uses it as the
 * canonical "use the data" sink (e.g. CWE416 UAF testcases pass a freed
 * pointer here). A no-op stub would mask the dereference from CBMC's
 * --pointer-check, producing a false `safe` verdict. Reading *line once
 * forces CBMC to see the access. The store-to-discarded-volatile keeps
 * the read live under aggressive optimization. */
void printLine(const char *line)
{
    volatile char c = line ? line[0] : 0;
    (void)c;
}
void printWLine(const wchar_t *line)
{
    volatile wchar_t c = line ? line[0] : 0;
    (void)c;
}
void printIntLine(int n)                               { (void)n; }
void printShortLine(short n)                           { (void)n; }
void printFloatLine(float n)                           { (void)n; }
void printLongLine(long n)                             { (void)n; }
void printLongLongLine(int64_t n)                      { (void)n; }
void printSizeTLine(size_t n)                          { (void)n; }
void printHexCharLine(char c)                          { (void)c; }
void printWcharLine(wchar_t c)                         { (void)c; }
void printUnsignedLine(unsigned n)                     { (void)n; }
void printHexUnsignedCharLine(unsigned char c)         { (void)c; }
void printDoubleLine(double n)                         { (void)n; }
void printBytesLine(const unsigned char *b, size_t n)  { (void)b; (void)n; }

struct _twoIntsStruct;
void printStructLine(const struct _twoIntsStruct *s)   { (void)s; }

size_t decodeHexChars(unsigned char *bytes, size_t numBytes, const char *hex)
{ (void)bytes; (void)numBytes; (void)hex; return 0; }
size_t decodeHexWChars(unsigned char *bytes, size_t numBytes, const wchar_t *hex)
{ (void)bytes; (void)numBytes; (void)hex; return 0; }

int globalReturnsTrue(void)  { return 1; }
int globalReturnsFalse(void) { return 0; }
int globalReturnsTrueOrFalse(void) {
    int x;  /* nondeterministic — CBMC will explore both branches */
    return x ? 1 : 0;
}
