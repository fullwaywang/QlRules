/**
 * @name linux-886e44c9298a6b428ae046e2fa092ca52e822e6a-netvsc_get_ethtool_stats
 * @id cpp/linux/886e44c9298a6b428ae046e2fa092ca52e822e6a/netvsc_get_ethtool_stats
 * @description linux-886e44c9298a6b428ae046e2fa092ca52e822e6a-netvsc_get_ethtool_stats 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vpcpu_sum_1548, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vpcpu_sum_1548
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_0))
}

predicate func_1(Variable vpcpu_sum_1548, Variable v__cpu_possible_mask) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vpcpu_sum_1548
		and target_1.getRValue().(FunctionCall).getTarget().hasName("kvmalloc_array")
		and target_1.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("cpumask_weight")
		and target_1.getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=v__cpu_possible_mask
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="64"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="3264"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

from Function func, Variable vpcpu_sum_1548, Variable v__cpu_possible_mask
where
not func_0(vpcpu_sum_1548, func)
and vpcpu_sum_1548.getType().hasName("netvsc_ethtool_pcpu_stats *")
and func_1(vpcpu_sum_1548, v__cpu_possible_mask)
and v__cpu_possible_mask.getType().hasName("cpumask")
and vpcpu_sum_1548.getParentScope+() = func
and not v__cpu_possible_mask.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
