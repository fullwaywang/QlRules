/**
 * @name linux-1f461dcdd296eecedaffffc6bae2bfa90bd7eb89-ppp_unregister_channel
 * @id cpp/linux/1f461dcdd296eecedaffffc6bae2bfa90bd7eb89/ppp_unregister_channel
 * @description linux-1f461dcdd296eecedaffffc6bae2bfa90bd7eb89-ppp_unregister_channel 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vpch_2384, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("put_net")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="chan_net"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpch_2384
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0))
}

predicate func_1(Variable vpch_2384, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chan_net"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpch_2384
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_1))
}

predicate func_2(Variable vpch_2384) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="list"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpch_2384)
}

from Function func, Variable vpch_2384
where
not func_0(vpch_2384, func)
and not func_1(vpch_2384, func)
and vpch_2384.getType().hasName("channel *")
and func_2(vpch_2384)
and vpch_2384.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
