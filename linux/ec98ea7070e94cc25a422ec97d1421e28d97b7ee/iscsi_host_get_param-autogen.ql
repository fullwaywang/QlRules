/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_host_get_param
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/iscsi_host_get_param
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_host_get_param 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_3703, Variable vihost_3705) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_3703
		and target_0.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="netdev"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vihost_3705)
}

predicate func_1(Parameter vbuf_3703, Variable vihost_3705) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sprintf")
		and not target_1.getTarget().hasName("sysfs_emit")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vbuf_3703
		and target_1.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="hwaddress"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vihost_3705)
}

predicate func_2(Parameter vbuf_3703, Variable vihost_3705) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sprintf")
		and not target_2.getTarget().hasName("sysfs_emit")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vbuf_3703
		and target_2.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_2.getArgument(2).(PointerFieldAccess).getTarget().getName()="initiatorname"
		and target_2.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vihost_3705)
}

from Function func, Parameter vbuf_3703, Variable vihost_3705
where
func_0(vbuf_3703, vihost_3705)
and func_1(vbuf_3703, vihost_3705)
and func_2(vbuf_3703, vihost_3705)
and vbuf_3703.getType().hasName("char *")
and vihost_3705.getType().hasName("iscsi_host *")
and vbuf_3703.getParentScope+() = func
and vihost_3705.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
