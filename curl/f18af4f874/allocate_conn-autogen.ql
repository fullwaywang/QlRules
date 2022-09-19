import cpp

predicate func_0(Function func) {
	exists(SizeofTypeOperator target_0 |
		target_0.getType().hasName("unsigned long")
		and target_0.getValue()="1456"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vdata, Variable vconn, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getType().hasName("unsigned char")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("unsigned char")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ssl_primary_config")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getType().hasName("unsigned char")
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("ssl_primary_config")
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vdata, Variable vconn, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getType().hasName("unsigned char")
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("unsigned char")
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proxy_ssl_config"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ssl_primary_config")
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getType().hasName("unsigned char")
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("ssl_primary_config")
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter vdata, Variable vconn
where
func_0(func)
and not func_1(vdata, vconn, func)
and not func_2(vdata, vconn, func)
and vdata.getType().hasName("Curl_easy *")
and vconn.getType().hasName("connectdata *")
and vdata.getParentScope+() = func
and vconn.getParentScope+() = func
select func, vdata, vconn
