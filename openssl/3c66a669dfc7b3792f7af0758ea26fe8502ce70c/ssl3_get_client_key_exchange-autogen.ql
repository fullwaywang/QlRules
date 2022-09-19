import cpp

predicate func_0(Variable vp) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("BUF_strdup")
		and not target_0.getTarget().hasName("BUF_strndup")
		and target_0.getType().hasName("char *")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vp)
}

from Function func, Variable vp
where
func_0(vp)
and vp.getType().hasName("unsigned char *")
and vp.getParentScope+() = func
select func, vp
