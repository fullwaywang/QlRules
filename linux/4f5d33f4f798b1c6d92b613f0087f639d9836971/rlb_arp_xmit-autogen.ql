/**
 * @name linux-4f5d33f4f798b1c6d92b613f0087f639d9836971-rlb_arp_xmit
 * @id cpp/linux/4f5d33f4f798b1c6d92b613f0087f639d9836971/rlb-arp-xmit
 * @description linux-4f5d33f4f798b1c6d92b613f0087f639d9836971-rlb_arp_xmit 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_656) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("dev_put")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_656
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("netif_is_bridge_master")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_656)
}

predicate func_2(Variable vdev_656) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("netif_is_bridge_master")
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_656)
}

predicate func_3(Variable vdev_656) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("netif_is_bridge_master")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vdev_656)
}

from Function func, Variable vdev_656
where
not func_0(vdev_656)
and func_2(vdev_656)
and vdev_656.getType().hasName("net_device *")
and func_3(vdev_656)
and vdev_656.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
