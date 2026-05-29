/**
 * @name Diagnostic: which net/ subdirs extracted
 * @kind table
 * @id touchstone/diag-netdirs
 */
import cpp

from string subdir, int n
where
  subdir = strictconcat(Function f |
      f.getFile().getAbsolutePath().matches("%/net/%") |
      f.getFile().getRelativePath().regexpCapture("(net/[^/]+)/.*", 1), ",")
    and n = 0
  or
  exists(string d |
    d = any(Function f | f.getFile().getAbsolutePath().matches("%/net/%") |
            f.getFile().getRelativePath().regexpCapture("(net/[^/]+)/.*", 1)) and
    subdir = d and
    n = count(Function f | f.getFile().getRelativePath().regexpCapture("(net/[^/]+)/.*", 1) = d))
select subdir, n order by n desc
