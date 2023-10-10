/**
 * @name dpdk-549de54c4f9fd36b2b11f3df7e81bf2567a2d526-vhost_user_set_inflight_fd
 * @id cpp/dpdk/549de54c4f9fd36b2b11f3df7e81bf2567a2d526/vhost-user-set-inflight-fd
 * @description dpdk-549de54c4f9fd36b2b11f3df7e81bf2567a2d526-lib/librte_vhost/vhost_user.c-vhost_user_set_inflight_fd CVE-2020-10726
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_1481, PointerFieldAccess target_2, PointerFieldAccess target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="addr"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1481
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdev_1481, PointerFieldAccess target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("munmap")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="addr"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1481
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1481
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vdev_1481, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="addr"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1481
}

predicate func_3(Variable vdev_1481, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="addr"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1481
}

from Function func, Variable vdev_1481, ExprStmt target_1, PointerFieldAccess target_2, PointerFieldAccess target_3
where
not func_0(vdev_1481, target_2, target_3)
and func_1(vdev_1481, target_2, target_1)
and func_2(vdev_1481, target_2)
and func_3(vdev_1481, target_3)
and vdev_1481.getType().hasName("virtio_net *")
and vdev_1481.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
