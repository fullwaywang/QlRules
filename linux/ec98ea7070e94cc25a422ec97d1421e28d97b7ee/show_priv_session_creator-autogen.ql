/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_priv_session_creator
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/show_priv_session_creator
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_priv_session_creator 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_4200, Variable vsession_4202) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_4200
		and target_0.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="creator"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_4202)
}

from Function func, Parameter vbuf_4200, Variable vsession_4202
where
func_0(vbuf_4200, vsession_4202)
and vbuf_4200.getType().hasName("char *")
and vsession_4202.getType().hasName("iscsi_cls_session *")
and vbuf_4200.getParentScope+() = func
and vsession_4202.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
