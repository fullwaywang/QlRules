/**
 * @name dpdk-af74f7db384ed149fe42b21dbd7975f8a54ef227-vhost_user_get_inflight_fd
 * @id cpp/dpdk/af74f7db384ed149fe42b21dbd7975f8a54ef227/vhost-user-get-inflight-fd
 * @description dpdk-af74f7db384ed149fe42b21dbd7975f8a54ef227-lib/vhost/vhost_user.c-vhost_user_get_inflight_fd CVE-2022-0669
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_1594, Variable vdev_1600, EqualityOperation target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("validate_msg_fds")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_1600
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vctx_1594
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctx_1594, EqualityOperation target_1) {
		target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1594
		and target_1.getAnOperand().(SizeofExprOperator).getValue()="24"
}

predicate func_2(Parameter vctx_1594, Variable vdev_1600, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("rte_log")
		and target_2.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="VHOST_CONFIG: (%s) invalid get_inflight_fd message size is %d\n"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="ifname"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1600
		and target_2.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg"
		and target_2.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1594
}

from Function func, Parameter vctx_1594, Variable vdev_1600, EqualityOperation target_1, ExprStmt target_2
where
not func_0(vctx_1594, vdev_1600, target_1, target_2, func)
and func_1(vctx_1594, target_1)
and func_2(vctx_1594, vdev_1600, target_2)
and vctx_1594.getType().hasName("vhu_msg_context *")
and vdev_1600.getType().hasName("virtio_net *")
and vctx_1594.getParentScope+() = func
and vdev_1600.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
