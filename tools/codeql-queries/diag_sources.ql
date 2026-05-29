/**
 * @name Diagnostic: source/sink population
 * @kind table
 * @id touchstone/diag-sources
 */
import cpp

predicate copyUser(FunctionCall fc) {
  fc.getTarget().getName() =
    ["copy_from_user", "_copy_from_user", "__copy_from_user", "memdup_user"]
}
predicate nlGetter(FunctionCall fc) {
  fc.getTarget().getName().regexpMatch("nla_get_.*|nlmsg_data|genlmsg_data|nla_data")
}

from string kind, int n
where
  kind = "copy_from_user-family call sites" and n = count(FunctionCall fc | copyUser(fc))
  or
  kind = "netlink getter (nla_get*/nlmsg_data/genlmsg_data) call sites" and
    n = count(FunctionCall fc | nlGetter(fc))
  or
  kind = "array-index exprs in net/" and
    n = count(ArrayExpr ae | ae.getFile().getRelativePath().matches("net/%"))
  or
  kind = "ethnl_default_requests[] index exprs" and
    n = count(ArrayExpr ae | ae.getArrayBase().toString().matches("%ethnl_default_requests%"))
select kind, n
