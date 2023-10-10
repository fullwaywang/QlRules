/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-item_length
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/item-length
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-column.c-item_length CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_24, FunctionCall target_2) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("strlen")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_24
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_24, UnaryMinusExpr target_1) {
		target_1.getValue()="-1"
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("utf8_strnwidth")
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_24
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_2(Parameter vs_24, FunctionCall target_2) {
		target_2.getTarget().hasName("utf8_strnwidth")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_24
		and target_2.getArgument(1) instanceof UnaryMinusExpr
		and target_2.getArgument(2).(Literal).getValue()="1"
}

from Function func, Parameter vs_24, UnaryMinusExpr target_1, FunctionCall target_2
where
not func_0(vs_24, target_2)
and func_1(vs_24, target_1)
and func_2(vs_24, target_2)
and vs_24.getType().hasName("const char *")
and vs_24.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
