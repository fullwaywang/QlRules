/**
 * @name dpdk-549de54c4f9fd36b2b11f3df7e81bf2567a2d526-vhost_user_get_inflight_fd
 * @id cpp/dpdk/549de54c4f9fd36b2b11f3df7e81bf2567a2d526/vhost-user-get-inflight-fd
 * @description dpdk-549de54c4f9fd36b2b11f3df7e81bf2567a2d526-lib/librte_vhost/vhost_user.c-vhost_user_get_inflight_fd CVE-2020-10726
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_1401, FunctionCall target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="addr"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1401
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("munmap")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="addr"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1401
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1401
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="addr"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1401
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0)
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdev_1401, FunctionCall target_1) {
		target_1.getTarget().hasName("vq_is_packed")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdev_1401
}

predicate func_2(Variable vdev_1401, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="addr"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inflight_info"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1401
}

from Function func, Variable vdev_1401, FunctionCall target_1, ExprStmt target_2
where
not func_0(vdev_1401, target_1, target_2, func)
and func_1(vdev_1401, target_1)
and func_2(vdev_1401, target_2)
and vdev_1401.getType().hasName("virtio_net *")
and vdev_1401.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
