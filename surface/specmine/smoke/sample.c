/* Phase 5.1 smoke fixture — synthetic C that exercises every guard kind. */

#include <stdio.h>

static int worker(int x)
{
    return x;
}

static int do_thing(int arg)
{
    return arg + 1;
}

static int caller_holds_lock(int *p)
{
    spin_lock(&p->lock);
    if (!p) {
        spin_unlock(&p->lock);
        return -1;
    }
    /* Expect at this callsite:
         lock_acquire: spin_held
         null_check:    p != NULL  (from `if (!p) return`)
    */
    worker(*p);
    spin_unlock(&p->lock);
    return 0;
}

static int caller_with_capable(int op)
{
    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    /* Expect:
         capability_check: capable(CAP_NET_ADMIN)
         early_return:     !(!capable(CAP_NET_ADMIN))
    */
    do_thing(op);
    return 0;
}

static int caller_in_if(int n)
{
    if (n > 0) {
        /* Expect enclosing_if predicate "n > 0" in_true_branch. */
        worker(n);
    } else {
        /* Expect enclosing_if predicate "n > 0" in_false_branch. */
        worker(-n);
    }
    return 0;
}

static int caller_rcu(int *arr)
{
    rcu_read_lock();
    BUG_ON(!arr);
    /* Expect lock_acquire rcu_read_lock_held, assert_neg !(!arr). */
    worker(arr[0]);
    rcu_read_unlock();
    /* After the unlock, the lock guard should be gone. */
    worker(arr[1]);
    return 0;
}

static int caller_no_guards(int q)
{
    /* Expect empty guard list. */
    worker(q);
    return q;
}
