import cpp

predicate func_2(Parameter vdata) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="proxy_ssl"
		and target_2.getType().hasName("ssl_config_data")
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_2.getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_3(Parameter vdata) {
	exists(ValueFieldAccess target_3 |
		target_3.getTarget().getName()="ssl"
		and target_3.getType().hasName("ssl_config_data")
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

from Function func, Parameter vdata
where
func_2(vdata)
and func_3(vdata)
and vdata.getType().hasName("Curl_easy *")
and vdata.getParentScope+() = func
select func, vdata
