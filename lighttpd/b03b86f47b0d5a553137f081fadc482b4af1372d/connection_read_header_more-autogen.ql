/**
 * @name lighttpd-b03b86f47b0d5a553137f081fadc482b4af1372d-connection_read_header_more
 * @id cpp/lighttpd/b03b86f47b0d5a553137f081fadc482b4af1372d/connection-read-header-more
 * @description lighttpd-b03b86f47b0d5a553137f081fadc482b4af1372d-src/connections.c-connection_read_header_more CVE-2022-30780
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ComplementExpr target_0 |
		target_0.getValue()="18446744073709535232"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func, SubExpr target_1) {
		target_1.getValue()="16383"
		and target_1.getEnclosingFunction() = func
}

from Function func, SubExpr target_1
where
not func_0(func)
and func_1(func, target_1)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
