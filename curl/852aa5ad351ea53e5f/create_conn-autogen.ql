/**
 * @name curl-852aa5ad351ea53e5f-create_conn
 * @id cpp/curl/852aa5ad351ea53e5f/create-conn
 * @description curl-852aa5ad351ea53e5f-create_conn CVE-2022-22576
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresult_3591, Variable vconn_3592, Parameter vdata_3587, Variable vCurl_cstrdup, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3587
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3592
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3587
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3592
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3591
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0))
}

predicate func_5(Variable vconn_3592) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="sasl_authzid"
		and target_5.getQualifier().(VariableAccess).getTarget()=vconn_3592)
}

predicate func_6(Parameter vdata_3587) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="set"
		and target_6.getQualifier().(VariableAccess).getTarget()=vdata_3587)
}

predicate func_7(Parameter vdata_3587, Variable vCurl_cstrdup) {
	exists(VariableCall target_7 |
		target_7.getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_7.getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_7.getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3587)
}

from Function func, Variable vresult_3591, Variable vconn_3592, Parameter vdata_3587, Variable vCurl_cstrdup
where
not func_0(vresult_3591, vconn_3592, vdata_3587, vCurl_cstrdup, func)
and vresult_3591.getType().hasName("CURLcode")
and vconn_3592.getType().hasName("connectdata *")
and func_5(vconn_3592)
and vdata_3587.getType().hasName("Curl_easy *")
and func_6(vdata_3587)
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and func_7(vdata_3587, vCurl_cstrdup)
and vresult_3591.getParentScope+() = func
and vconn_3592.getParentScope+() = func
and vdata_3587.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
