import cpp

predicate func_3(Parameter vdata, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getType().hasName("curl_blob *")
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="issuercert_blob"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("curl_blob *")
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("ssl_primary_config")
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getType().hasName("curl_blob *")
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="blobs"
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getType().hasName("curl_blob *[8]")
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_5(Parameter vdata) {
	exists(ArrayExpr target_5 |
		target_5.getType().hasName("char *")
		and target_5.getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_5.getArrayBase().(ValueFieldAccess).getType().hasName("char *[80]")
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="issuercert"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("char *")
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("ssl_config_data")
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_7(Parameter vdata) {
	exists(ArrayExpr target_7 |
		target_7.getType().hasName("char *")
		and target_7.getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_7.getArrayBase().(ValueFieldAccess).getType().hasName("char *[80]")
		and target_7.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_7.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="issuercert"
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("char *")
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("ssl_config_data")
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

from Function func, Parameter vdata
where
not func_3(vdata, func)
and func_5(vdata)
and func_7(vdata)
and vdata.getType().hasName("Curl_easy *")
and vdata.getParentScope+() = func
select func, vdata
