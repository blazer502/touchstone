/* Phase 5.2 smoke fixture — concentrated callsite pattern with a deliberate
 * outlier. The fictional callee `lookup_thing()` is called from 6 direct
 * callers; 5/6 acquire rcu_read_lock first, one does not. At tau=0.83+, mining
 * yields exactly one contract ("rcu_read_lock_held") and exactly one outlier
 * (caller_buggy at the unprotected callsite).
 *
 * One-hop establishment check fixture: `safe_wrapper` calls lookup_thing
 * without acquiring RCU itself, but is invoked by 4 callers who do hold RCU.
 * Those 4 callsites of safe_wrapper give safe_wrapper its own mined contract
 * `rcu_read_lock_held` (at sufficient support). When the miner then evaluates
 * the (lookup_thing, safe_wrapper) outlier, the one-hop check sees
 * safe_wrapper carries rcu_read_lock_held as its own contract, so
 * local_establishment = 1.0 and suspicion drops to 0.
 *
 * Multi-line bodies are required: 5.1's snapshot semantics deliberately
 * exclude guards on the same line as the callsite. Real kernel code is
 * multi-line so this matches the production case.
 */

static int lookup_thing(int x)
{
    return x + 1;
}

static int safe_wrapper(int x)
{
    /* No explicit acquire here — safe_wrapper relies on its callers'
     * established RCU context, which mining-of-safe_wrapper codifies. */
    return lookup_thing(x);
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

/* THE BUG: lookup_thing called without rcu_read_lock — only caller without it. */
static int caller_buggy(int x)
{
    int r;
    r = lookup_thing(x);
    return r;
}

/* These four call safe_wrapper under RCU. */
static int caller_o(int x)
{
    int r;
    rcu_read_lock();
    r = safe_wrapper(x);
    rcu_read_unlock();
    return r;
}

static int caller_p(int x)
{
    int r;
    rcu_read_lock();
    r = safe_wrapper(x);
    rcu_read_unlock();
    return r;
}

static int caller_q(int x)
{
    int r;
    rcu_read_lock();
    r = safe_wrapper(x);
    rcu_read_unlock();
    return r;
}

static int caller_r(int x)
{
    int r;
    rcu_read_lock();
    r = safe_wrapper(x);
    rcu_read_unlock();
    return r;
}
