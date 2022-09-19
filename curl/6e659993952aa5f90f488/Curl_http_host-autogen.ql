import cpp

predicate func_0(Parameter vdata, Parameter vconn) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getType().hasName("unsigned int")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="first_remote_protocol"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("unsigned int")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("UrlState")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="protocol"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getType().hasName("unsigned int")
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("const Curl_handler *")
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="this_is_a_follow"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata)
}

from Function func, Parameter vdata, Parameter vconn
where
not func_0(vdata, vconn)
and vdata.getType().hasName("Curl_easy *")
and vconn.getType().hasName("connectdata *")
and vdata.getParentScope+() = func
and vconn.getParentScope+() = func
select func, vdata, vconn
