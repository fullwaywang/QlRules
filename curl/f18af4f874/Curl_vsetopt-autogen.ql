import cpp

predicate func_0(Variable varg, Parameter vdata) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getType().hasName("unsigned char")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("unsigned char")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("ssl_primary_config")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getType().hasName("long")
		and target_0.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=varg
		and target_0.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255")
}

predicate func_1(Variable varg, Parameter vdata) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getType().hasName("unsigned char")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("unsigned char")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("ssl_primary_config")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getType().hasName("long")
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=varg
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255")
}

from Function func, Variable varg, Parameter vdata
where
not func_0(varg, vdata)
and not func_1(varg, vdata)
and varg.getType().hasName("long")
and vdata.getType().hasName("Curl_easy *")
and varg.getParentScope+() = func
and vdata.getParentScope+() = func
select func, varg, vdata
