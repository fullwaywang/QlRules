import cpp

predicate func_0(Parameter vdata) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("allow_auth_to_host")
		and not target_0.getTarget().hasName("Curl_allow_auth_to_host")
		and target_0.getType().hasName("bool")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata)
}

from Function func, Parameter vdata
where
func_0(vdata)
and vdata.getType().hasName("Curl_easy *")
and vdata.getParentScope+() = func
select func, vdata
