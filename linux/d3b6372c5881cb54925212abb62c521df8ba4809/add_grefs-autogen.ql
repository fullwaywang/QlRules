/**
 * @name linux-d3b6372c5881cb54925212abb62c521df8ba4809-add_grefs
 * @id cpp/linux/d3b6372c5881cb54925212abb62c521df8ba4809/add_grefs
 * @description linux-d3b6372c5881cb54925212abb62c521df8ba4809-add_grefs CVE-2022-23039
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vqueue_gref_125, Variable vgref_list, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("list_empty")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vqueue_gref_125
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("list_splice_tail")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vqueue_gref_125
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgref_list
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Variable vqueue_gref_125, Variable vgref_list
where
func_0(vqueue_gref_125, vgref_list, func)
and vqueue_gref_125.getType().hasName("list_head")
and vgref_list.getType().hasName("list_head")
and vqueue_gref_125.getParentScope+() = func
and not vgref_list.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
