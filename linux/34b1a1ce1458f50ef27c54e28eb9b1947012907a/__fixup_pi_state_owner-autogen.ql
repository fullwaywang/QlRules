/**
 * @name linux-34b1a1ce1458f50ef27c54e28eb9b1947012907a-__fixup_pi_state_owner
 * @id cpp/linux/34b1a1ce1458f50ef27c54e28eb9b1947012907a/__fixup_pi_state_owner
 * @description linux-34b1a1ce1458f50ef27c54e28eb9b1947012907a-__fixup_pi_state_owner 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vpi_state_2335, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("pi_state_update_owner")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_2335
		and target_0.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_0.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_0.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_2335
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_0))
}

predicate func_1(Variable vpi_state_2335) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="owner"
		and target_1.getQualifier().(VariableAccess).getTarget()=vpi_state_2335)
}

from Function func, Variable vpi_state_2335
where
not func_0(vpi_state_2335, func)
and vpi_state_2335.getType().hasName("futex_pi_state *")
and func_1(vpi_state_2335)
and vpi_state_2335.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
