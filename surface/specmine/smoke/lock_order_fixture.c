/* Lock-order mining smoke fixture.
 *
 * Convention: acquire `a_lock` before `b_lock` (outer A -> inner B). Five
 * functions follow it. ONE function (buggy_inverter) takes them in the
 * opposite order (B -> A), closing a 2-cycle. The miner should:
 *   - establish the dominant order a_lock -> b_lock (weight 5),
 *   - detect the 2-cycle {a_lock, b_lock},
 *   - flag buggy_inverter's b_lock -> a_lock as the minority-weight inversion
 *     lead (weight 1, suspicion ~0.83).
 *
 * Also a benign 3-lock chain (x -> y -> z) with no inversion, to confirm the
 * miner does NOT report a cycle where none exists.
 */

struct obj { int a_lock; int b_lock; int x_lock; int y_lock; int z_lock; };

void spin_lock(int *l);
void spin_unlock(int *l);

static void worker_a(struct obj *o)
{
    spin_lock(&o->a_lock);
    spin_lock(&o->b_lock);
    spin_unlock(&o->b_lock);
    spin_unlock(&o->a_lock);
}

static void worker_b(struct obj *o)
{
    spin_lock(&o->a_lock);
    spin_lock(&o->b_lock);
    spin_unlock(&o->b_lock);
    spin_unlock(&o->a_lock);
}

static void worker_c(struct obj *o)
{
    spin_lock(&o->a_lock);
    spin_lock(&o->b_lock);
    spin_unlock(&o->b_lock);
    spin_unlock(&o->a_lock);
}

static void worker_d(struct obj *o)
{
    spin_lock(&o->a_lock);
    spin_lock(&o->b_lock);
    spin_unlock(&o->b_lock);
    spin_unlock(&o->a_lock);
}

static void worker_e(struct obj *o)
{
    spin_lock(&o->a_lock);
    spin_lock(&o->b_lock);
    spin_unlock(&o->b_lock);
    spin_unlock(&o->a_lock);
}

/* THE BUG: inverts the a_lock/b_lock order -> closes a 2-cycle. */
static void buggy_inverter(struct obj *o)
{
    spin_lock(&o->b_lock);
    spin_lock(&o->a_lock);
    spin_unlock(&o->a_lock);
    spin_unlock(&o->b_lock);
}

/* Benign 3-lock chain: x -> y -> z, consistent everywhere, no cycle. */
static void chain_one(struct obj *o)
{
    spin_lock(&o->x_lock);
    spin_lock(&o->y_lock);
    spin_lock(&o->z_lock);
    spin_unlock(&o->z_lock);
    spin_unlock(&o->y_lock);
    spin_unlock(&o->x_lock);
}

static void chain_two(struct obj *o)
{
    spin_lock(&o->x_lock);
    spin_lock(&o->y_lock);
    spin_unlock(&o->y_lock);
    spin_unlock(&o->x_lock);
}
