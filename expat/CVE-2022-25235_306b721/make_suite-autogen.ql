/**
 * @name expat-306b72134f157bbfd1637b20a22cabf4acfa136a-make_suite
 * @id cpp/expat/306b72134f157bbfd1637b20a22cabf4acfa136a/make-suite
 * @description expat-306b72134f157bbfd1637b20a22cabf4acfa136a-expat/tests/runtests.c-make_suite CVE-2022-25235
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtc_basic_11669, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_basic_11669
		and (func.getEntryPoint().(BlockStmt).getStmt(194)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(194).getFollowingStmt()=target_0)
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vtc_basic_11669, ExprStmt target_4, ExprStmt target_5, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_basic_11669
		and (func.getEntryPoint().(BlockStmt).getStmt(203)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(203).getFollowingStmt()=target_1)
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vtc_basic_11669, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_basic_11669
}

predicate func_3(Variable vtc_basic_11669, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_basic_11669
}

predicate func_4(Variable vtc_basic_11669, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_basic_11669
}

predicate func_5(Variable vtc_basic_11669, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("tcase_add_test")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtc_basic_11669
}

from Function func, Variable vtc_basic_11669, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vtc_basic_11669, target_2, target_3, func)
and not func_1(vtc_basic_11669, target_4, target_5, func)
and func_2(vtc_basic_11669, target_2)
and func_3(vtc_basic_11669, target_3)
and func_4(vtc_basic_11669, target_4)
and func_5(vtc_basic_11669, target_5)
and vtc_basic_11669.getType().hasName("TCase *")
and vtc_basic_11669.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
