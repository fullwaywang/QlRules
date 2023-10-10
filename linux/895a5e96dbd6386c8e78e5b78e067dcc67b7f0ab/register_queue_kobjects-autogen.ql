/**
 * @name linux-895a5e96dbd6386c8e78e5b78e067dcc67b7f0ab-register_queue_kobjects
 * @id cpp/linux/895a5e96dbd6386c8e78e5b78e067dcc67b7f0ab/register_queue_kobjects
 * @description linux-895a5e96dbd6386c8e78e5b78e067dcc67b7f0ab-register_queue_kobjects 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdev_1522, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kset_unregister")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="queues_kset"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1522
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vdev_1522, Variable vrxq_1524) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("net_rx_queue_update_kobjects")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdev_1522
		and target_1.getArgument(1).(VariableAccess).getTarget()=vrxq_1524
		and target_1.getArgument(2).(Literal).getValue()="0")
}

from Function func, Parameter vdev_1522, Variable vrxq_1524
where
not func_0(vdev_1522, func)
and vdev_1522.getType().hasName("net_device *")
and func_1(vdev_1522, vrxq_1524)
and vrxq_1524.getType().hasName("int")
and vdev_1522.getParentScope+() = func
and vrxq_1524.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
