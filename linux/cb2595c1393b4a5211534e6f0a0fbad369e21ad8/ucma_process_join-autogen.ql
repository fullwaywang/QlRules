/**
 * @name linux-cb2595c1393b4a5211534e6f0a0fbad369e21ad8-ucma_process_join
 * @id cpp/linux/cb2595c1393b4a5211534e6f0a0fbad369e21ad8/ucma_process_join
 * @description linux-cb2595c1393b4a5211534e6f0a0fbad369e21ad8-ucma_process_join 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vmc_1380, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("idr_replace")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("idr")
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmc_1380
		and target_0.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="id"
		and target_0.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmc_1380
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_0))
}

predicate func_1(Variable vmut, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmut
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_1))
}

predicate func_2(Variable vmut, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmut
		and (func.getEntryPoint().(BlockStmt).getStmt(34)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(34).getFollowingStmt()=target_2))
}

predicate func_3(Variable vmc_1380) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="id"
		and target_3.getQualifier().(VariableAccess).getTarget()=vmc_1380)
}

from Function func, Variable vmc_1380, Variable vmut
where
not func_0(vmc_1380, func)
and not func_1(vmut, func)
and not func_2(vmut, func)
and vmc_1380.getType().hasName("ucma_multicast *")
and func_3(vmc_1380)
and vmut.getType().hasName("mutex")
and vmc_1380.getParentScope+() = func
and not vmut.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
