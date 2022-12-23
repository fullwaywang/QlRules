/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_priv_session_target_id
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/show_priv_session_target_id
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_priv_session_target_id 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_4209, Variable vsession_4211) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_4209
		and target_0.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="target_id"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_4211)
}

from Function func, Parameter vbuf_4209, Variable vsession_4211
where
func_0(vbuf_4209, vsession_4211)
and vbuf_4209.getType().hasName("char *")
and vsession_4211.getType().hasName("iscsi_cls_session *")
and vbuf_4209.getParentScope+() = func
and vsession_4211.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
