import cpp

predicate func_20(Parameter vdata) {
	exists(ValueFieldAccess target_20 |
		target_20.getTarget().getName()="proxy_ssl"
		and target_20.getType().hasName("ssl_config_data")
		and target_20.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_20.getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_21(Parameter vdata) {
	exists(ValueFieldAccess target_21 |
		target_21.getTarget().getName()="ssl"
		and target_21.getType().hasName("ssl_config_data")
		and target_21.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_21.getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_21.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_22(Parameter vdata) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="set"
		and target_22.getType().hasName("UserDefined")
		and target_22.getQualifier().(VariableAccess).getTarget()=vdata)
}

from Function func, Parameter vdata, Parameter vconn
where
func_20(vdata)
and func_21(vdata)
and func_22(vdata)
and vdata.getType().hasName("Curl_easy *")
and vconn.getType().hasName("connectdata *")
and vdata.getParentScope+() = func
and vconn.getParentScope+() = func
select func, vdata, vconn
