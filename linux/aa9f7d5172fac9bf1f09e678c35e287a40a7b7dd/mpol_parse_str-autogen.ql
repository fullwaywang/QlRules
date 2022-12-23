/**
 * @name linux-aa9f7d5172fac9bf1f09e678c35e287a40a7b7dd-mpol_parse_str
 * @id cpp/linux/aa9f7d5172fac9bf1f09e678c35e287a40a7b7dd/mpol_parse_str
 * @description linux-aa9f7d5172fac9bf1f09e678c35e287a40a7b7dd-mpol_parse_str 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnodes_2876, Variable vnodelist_2877) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__nodes_empty")
		and target_0.getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnodes_2876
		and target_0.getCondition().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="1024"
		and target_0.getCondition().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="10"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnodelist_2877)
}

from Function func, Variable vnodes_2876, Variable vnodelist_2877
where
not func_0(vnodes_2876, vnodelist_2877)
and vnodes_2876.getType().hasName("nodemask_t")
and vnodelist_2877.getType().hasName("char *")
and vnodes_2876.getParentScope+() = func
and vnodelist_2877.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
