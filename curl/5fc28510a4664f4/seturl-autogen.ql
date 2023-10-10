/**
 * @name curl-5fc28510a4664f4-seturl
 * @id cpp/curl/5fc28510a4664f4/seturl
 * @description curl-5fc28510a4664f4-lib/urlapi.c-seturl CVE-2019-5435
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vurllen_634, ExprStmt target_1, AddExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vurllen_634
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8000000"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vurllen_634, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vurllen_634
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_2(Variable vurllen_634, AddExpr target_2) {
		target_2.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vurllen_634
		and target_2.getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getAnOperand().(Literal).getValue()="2"
}

from Function func, Variable vurllen_634, ExprStmt target_1, AddExpr target_2
where
not func_0(vurllen_634, target_1, target_2, func)
and func_1(vurllen_634, target_1)
and func_2(vurllen_634, target_2)
and vurllen_634.getType().hasName("size_t")
and vurllen_634.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
