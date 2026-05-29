/**
 * @name Kernel user-controlled array index
 * @description An array is indexed (or a memcpy/memset is sized) by a value
 *              derived from kernel user input (copy_from_user / get_user /
 *              netlink attribute getters / netlink message payload) with global
 *              interprocedural taint. This is the weaponizable shape Smatch flags
 *              as `user_rl=` — but CodeQL's global dataflow can cross the function
 *              boundary (including, where modeled, the dispatch edge) that Smatch's
 *              per-function user_rl misses. Soundness unchanged: a hit is a
 *              *candidate*; the sanitizer/repro oracle decides.
 * @kind path-problem
 * @problem.severity warning
 * @id touchstone/kernel-user-controlled-array-index
 * @tags security kernel
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow

/** A call to a kernel routine that copies attacker-controlled bytes into arg 0. */
predicate copiesUserInto(FunctionCall fc, Expr dest) {
  fc.getTarget().getName() =
    ["copy_from_user", "_copy_from_user", "__copy_from_user", "memdup_user"] and
  dest = fc.getArgument(0)
}

/** A netlink/genetlink attribute getter — returns an attacker-controlled scalar. */
predicate nlAttrGetter(FunctionCall fc) {
  fc.getTarget().getName().regexpMatch("nla_get_.*|nlmsg_data|genlmsg_data|nla_data")
}

module KernelUserIndexConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(FunctionCall fc | copiesUserInto(fc, source.asDefiningArgument()))
    or
    exists(FunctionCall fc | nlAttrGetter(fc) and source.asExpr() = fc)
  }

  predicate isSink(DataFlow::Node sink) {
    // array index ...
    exists(ArrayExpr ae | sink.asExpr() = ae.getArrayOffset())
    or
    // ... or the size operand of a bulk copy (length-controlled overflow).
    exists(FunctionCall fc |
      fc.getTarget().getName() = ["memcpy", "memmove", "memset", "copy_to_user"] and
      sink.asExpr() = fc.getArgument(2)
    )
  }
}

module KernelUserIndexFlow = TaintTracking::Global<KernelUserIndexConfig>;

import KernelUserIndexFlow::PathGraph

from KernelUserIndexFlow::PathNode source, KernelUserIndexFlow::PathNode sink
where KernelUserIndexFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Array index / copy size derives from kernel user input at $@.",
  source.getNode(), source.getNode().toString()
