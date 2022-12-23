/**
 * @name linux-c3e2219216c92919a6bd1711f340f5faa98695e6-blk_cleanup_queue
 * @id cpp/linux/c3e2219216c92919a6bd1711f340f5faa98695e6/blk-cleanup-queue
 * @description linux-c3e2219216c92919a6bd1711f340f5faa98695e6-blk_cleanup_queue 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vq_292, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sysfs_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_292
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vq_292, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="elevator"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_292
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("blk_mq_sched_free_requests")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_292
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vq_292, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sysfs_lock"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_292
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vq_292) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("blk_mq_exit_queue")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vq_292)
}

from Function func, Parameter vq_292
where
not func_0(vq_292, func)
and not func_1(vq_292, func)
and not func_2(vq_292, func)
and vq_292.getType().hasName("request_queue *")
and func_3(vq_292)
and vq_292.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
