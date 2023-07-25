/**
 * @name expat-56967f83d68d5fc750f9e66a9a76756c94c7c173-make_suite
 * @id cpp/expat/56967f83d68d5fc750f9e66a9a76756c94c7c173/make-suite
 * @description expat-56967f83d68d5fc750f9e66a9a76756c94c7c173-expat/tests/runtests.c-make_suite CVE-2022-43680
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtc_alloc_12056, ExprStmt target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test__ifdef_xml_dtd")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_alloc_12056
		and (func.getEntryPoint().(BlockStmt).getStmt(330)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(330).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vtc_alloc_12056, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_alloc_12056
}

from Function func, Variable vtc_alloc_12056, ExprStmt target_1
where
not func_0(vtc_alloc_12056, target_1, func)
and func_1(vtc_alloc_12056, target_1)
and vtc_alloc_12056.getType().hasName("TCase *")
and vtc_alloc_12056.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
