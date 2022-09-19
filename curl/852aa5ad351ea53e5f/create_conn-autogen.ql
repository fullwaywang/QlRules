import cpp

predicate func_0(Variable vresult, Variable vconn, Parameter vdata, Variable vCurl_cstrdup, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ArrayExpr).getType().hasName("char *")
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getType().hasName("char *[81]")
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("char *")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Variable vresult, Variable vconn, Parameter vdata, Variable vCurl_cstrdup
where
not func_0(vresult, vconn, vdata, vCurl_cstrdup, func)
and vresult.getType().hasName("CURLcode")
and vconn.getType().hasName("connectdata *")
and vdata.getType().hasName("Curl_easy *")
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vresult.getParentScope+() = func
and vconn.getParentScope+() = func
and vdata.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
select func, vresult, vconn, vdata, vCurl_cstrdup
