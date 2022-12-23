/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_priv_session_state
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/show_priv_session_state
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_priv_session_state 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_4191, Variable vsession_4193) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_4191
		and target_0.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_0.getArgument(2).(FunctionCall).getTarget().hasName("iscsi_session_state_name")
		and target_0.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_4193)
}

from Function func, Parameter vbuf_4191, Variable vsession_4193
where
func_0(vbuf_4191, vsession_4193)
and vbuf_4191.getType().hasName("char *")
and vsession_4193.getType().hasName("iscsi_cls_session *")
and vbuf_4191.getParentScope+() = func
and vsession_4193.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
