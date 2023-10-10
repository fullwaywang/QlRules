/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_transport_handle
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/show_transport_handle
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_transport_handle 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_132, Variable vpriv_134) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_132
		and target_0.getArgument(1).(StringLiteral).getValue()="%llu\n"
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="iscsi_transport"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_134)
}

from Function func, Parameter vbuf_132, Variable vpriv_134
where
func_0(vbuf_132, vpriv_134)
and vbuf_132.getType().hasName("char *")
and vpriv_134.getType().hasName("iscsi_internal *")
and vbuf_132.getParentScope+() = func
and vpriv_134.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
