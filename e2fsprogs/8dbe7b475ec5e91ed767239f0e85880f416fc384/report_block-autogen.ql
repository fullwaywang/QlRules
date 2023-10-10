/**
 * @name e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-report_block
 * @id cpp/e2fsprogs/8dbe7b475ec5e91ed767239f0e85880f416fc384/report-block
 * @description e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-lib/support/quotaio_tree.c-report_block CVE-2019-5094
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(UnaryMinusExpr target_1 |
		target_1.getValue()="-1"
		and target_1.getEnclosingFunction() = func)
}

from Function func, Literal target_0
where
func_0(func, target_0)
and not func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
