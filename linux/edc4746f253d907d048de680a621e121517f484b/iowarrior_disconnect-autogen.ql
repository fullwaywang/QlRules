/**
 * @name linux-edc4746f253d907d048de680a621e121517f484b-iowarrior_disconnect
 * @id cpp/linux/edc4746f253d907d048de680a621e121517f484b/iowarrior_disconnect
 * @description linux-edc4746f253d907d048de680a621e121517f484b-iowarrior_disconnect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_863) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mutex"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_863
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="opened"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_863)
}

predicate func_2(Variable vdev_863) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="write_wait"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdev_863)
}

from Function func, Variable vdev_863
where
not func_0(vdev_863)
and vdev_863.getType().hasName("iowarrior *")
and func_2(vdev_863)
and vdev_863.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
