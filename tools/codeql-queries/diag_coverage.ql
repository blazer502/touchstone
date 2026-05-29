/**
 * @name Diagnostic: extraction coverage
 * @kind table
 * @id touchstone/diag-coverage
 */
import cpp

from string bucket, int n
where
  bucket = "total defined functions" and n = count(Function f | f.hasDefinition())
  or
  bucket = "functions in /net/ (abs path)" and
    n = count(Function f | f.getFile().getAbsolutePath().matches("%/net/%"))
  or
  bucket = "functions in /net/ethtool/ (abs path)" and
    n = count(Function f | f.getFile().getAbsolutePath().matches("%/net/ethtool/%"))
  or
  bucket = "functions in /fs/ (abs path)" and
    n = count(Function f | f.getFile().getAbsolutePath().matches("%/fs/%"))
  or
  bucket = "ethnl_default_start present" and
    n = count(Function f | f.getName() = "ethnl_default_start")
  or
  bucket = "prio_tune present" and
    n = count(Function f | f.getName() = "prio_tune")
  or
  bucket = "ArrayExpr total (whole DB)" and n = count(ArrayExpr ae)
select bucket, n
