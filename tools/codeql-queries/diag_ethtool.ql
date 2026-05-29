/**
 * @name Diagnostic: ethtool candidate representation
 * @kind table
 * @id touchstone/diag-ethtool
 */
import cpp

from ArrayExpr ae, string base, string path, int line
where
  ae.getFile().getBaseName() = "netlink.c" and
  ae.getFile().getAbsolutePath().matches("%ethtool%") and
  base = ae.getArrayBase().toString() and
  path = ae.getFile().getRelativePath() and
  line = ae.getLocation().getStartLine()
select path, line, base, ae.getArrayOffset().toString()
