/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_conn_state
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/show_conn_state
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-show_conn_state 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_3957, Variable vstate_3960) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_3957
		and target_0.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_0.getArgument(2).(VariableAccess).getTarget()=vstate_3960)
}

from Function func, Parameter vbuf_3957, Variable vstate_3960
where
func_0(vbuf_3957, vstate_3960)
and vbuf_3957.getType().hasName("char *")
and vstate_3960.getType().hasName("const char *")
and vbuf_3957.getParentScope+() = func
and vstate_3960.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
