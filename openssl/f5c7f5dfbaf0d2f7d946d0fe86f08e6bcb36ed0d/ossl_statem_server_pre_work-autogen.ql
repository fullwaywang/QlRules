import cpp

predicate func_0(Parameter vs) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("dtls1_clear_record_buffer")
		and not target_0.getTarget().hasName("dtls1_clear_sent_buffer")
		and target_0.getType().hasName("void")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs)
}

from Function func, Parameter vs
where
func_0(vs)
and vs.getType().hasName("SSL *")
and vs.getParentScope+() = func
select func, vs
