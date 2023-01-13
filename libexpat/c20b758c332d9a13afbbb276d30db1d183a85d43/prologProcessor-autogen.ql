/**
 * @name libexpat-c20b758c332d9a13afbbb276d30db1d183a85d43-prologProcessor
 * @id cpp/libexpat/c20b758c332d9a13afbbb276d30db1d183a85d43/prologProcessor
 * @description libexpat-c20b758c332d9a13afbbb276d30db1d183a85d43-prologProcessor 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
