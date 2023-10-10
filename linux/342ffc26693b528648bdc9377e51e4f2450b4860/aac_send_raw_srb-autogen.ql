/**
 * @name linux-342ffc26693b528648bdc9377e51e4f2450b4860-aac_send_raw_srb
 * @id cpp/linux/342ffc26693b528648bdc9377e51e4f2450b4860/aac-send-raw-srb
 * @description linux-342ffc26693b528648bdc9377e51e4f2450b4860-aac_send_raw_srb NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vis_native_device_499, Variable vreply_950) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vreply_950
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="52"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vreply_950
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vis_native_device_499)
}

from Function func, Variable vis_native_device_499, Variable vreply_950
where
not func_0(vis_native_device_499, vreply_950)
and vis_native_device_499.getType().hasName("int")
and vreply_950.getType().hasName("aac_srb_reply")
and vis_native_device_499.getParentScope+() = func
and vreply_950.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
