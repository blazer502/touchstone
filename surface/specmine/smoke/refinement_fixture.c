/* Phase 5.5 refinement smoke fixture.
 *
 * The setup is the same as 5.2's mining_fixture: 10 callers acquire RCU before
 * calling `lookup_thing` (a strong mined-contract: rcu_read_lock_held at
 * 10/11 = 90.9% support). The outlier `caller_loopy_buggy` does NOT acquire
 * RCU AND contains a `for` loop that iterates an unbounded number of times.
 *
 * Phase 5.3 verification at --unwind=1 should land this outlier as
 * `inconclusive` (unwinding-assertion failure: the loop body wants to execute
 * more than 1 iteration). Phase 5.5 invokes the synthesizer / rule-based
 * fallback to propose `__CPROVER_assume(arg0 >= 0); __CPROVER_assume(arg0 <= K);`
 * preconditions that bound the symbolic argument. The re-verification at
 * --unwind=8 with the bound in place now decides: the rcu_read_lock_held
 * assertion fires inside the wrapper on each loop iteration → unsafe →
 * disposition flips from `inconclusive` to `confirmed`.
 */

static int lookup_thing(int x)
{
    return x + 1;
}

static int caller_a(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_b(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_c(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_d(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_e(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_f(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_g(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_h(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_i(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_j(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

/* THE OUTLIER:
 *  - no rcu_read_lock() acquire,
 *  - calls lookup_thing inside a for-loop whose upper bound is symbolic.
 *
 * At --unwind=1 CBMC reports inconclusive (unwinding-assertion failure).
 * Phase 5.5 refinement bounds `arg0` so CBMC can decide at a higher unwind.
 */
static int caller_loopy_buggy(int n)
{
    int i, r = 0;
    for (i = 0; i < n; i++) {
        r += lookup_thing(i);
    }
    return r;
}
