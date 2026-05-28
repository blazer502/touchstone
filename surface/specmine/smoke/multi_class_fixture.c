/* Phase 5.6 multi-class smoke fixture.
 *
 * Two callees with two different mined-contract classes:
 *
 *   1. lookup_thing  → mined contract: rcu_read_lock_held (locking class)
 *      10 callers acquire RCU before calling; 1 outlier `caller_buggy_lock`
 *      calls without RCU.
 *
 *   2. process_item  → mined contract: !(IS_ERR(item)) (null_init class)
 *      6 callers check IS_ERR(item) and early-return on error; 1 outlier
 *      `caller_buggy_null` calls process_item without checking.
 *
 * Phase 5.6 closed-loop should:
 *   - mine both contracts (locking + null_init);
 *   - rank 2 outliers (one per class) with suspicion ≥ τ;
 *   - 5.3 verify each → both `confirmed` with witness;
 *   - 5.4 report renders ≥2 vuln classes with confirmed leads;
 *   - 5.6 metrics adapter reports the headline.
 *
 * Final result demonstrates the §3b done-when: ≥1 confirmed lead across ≥2
 * vuln classes including ≥1 non-memory-safety class (locking is non-memory-
 * safety; null_init is memory-safety-shaped).
 */

/* --- Locking-class side (callee: lookup_thing) --- */

static int lookup_thing(int x)
{
    return x + 1;
}

static int caller_l_a(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_b(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_c(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_d(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_e(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_f(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_g(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_h(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_i(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

static int caller_l_j(int x)
{
    int r;
    rcu_read_lock();
    r = lookup_thing(x);
    rcu_read_unlock();
    return r;
}

/* The locking outlier: no RCU acquire before lookup_thing. */
static int caller_buggy_lock(int x)
{
    int r;
    r = lookup_thing(x);
    return r;
}

/* --- Null/IS_ERR class side (callee: process_item) --- */

static int process_item(int item)
{
    return item * 2;
}

static int caller_n_a(int item)
{
    if (IS_ERR(item))
        return -1;
    return process_item(item);
}

static int caller_n_b(int item)
{
    if (IS_ERR(item))
        return -1;
    return process_item(item);
}

static int caller_n_c(int item)
{
    if (IS_ERR(item))
        return -1;
    return process_item(item);
}

static int caller_n_d(int item)
{
    if (IS_ERR(item))
        return -1;
    return process_item(item);
}

static int caller_n_e(int item)
{
    if (IS_ERR(item))
        return -1;
    return process_item(item);
}

static int caller_n_f(int item)
{
    if (IS_ERR(item))
        return -1;
    return process_item(item);
}

/* The null_init outlier: no IS_ERR check before process_item. */
static int caller_buggy_null(int item)
{
    return process_item(item);
}
