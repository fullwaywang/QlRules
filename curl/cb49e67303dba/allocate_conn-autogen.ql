/**
 * @name curl-cb49e67303dba-allocate_conn
 * @id cpp/curl/cb49e67303dba/allocate-conn
 * @description curl-cb49e67303dba-lib/url.c-allocate_conn CVE-2023-27536
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_1481, Parameter vdata_1479, ExprStmt target_1, ReturnStmt target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gssapi_delegation"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1481
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="gssapi_delegation"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1479
		and (func.getEntryPoint().(BlockStmt).getStmt(40)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(40).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vconn_1481, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lastused"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1481
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_now")
}

predicate func_2(Variable vconn_1481, ReturnStmt target_2) {
		target_2.getExpr().(VariableAccess).getTarget()=vconn_1481
}

predicate func_3(Variable vconn_1481, Parameter vdata_1479, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="closesocket_client"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1481
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="closesocket_client"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1479
}

from Function func, Variable vconn_1481, Parameter vdata_1479, ExprStmt target_1, ReturnStmt target_2, ExprStmt target_3
where
not func_0(vconn_1481, vdata_1479, target_1, target_2, target_3, func)
and func_1(vconn_1481, target_1)
and func_2(vconn_1481, target_2)
and func_3(vconn_1481, vdata_1479, target_3)
and vconn_1481.getType().hasName("connectdata *")
and vdata_1479.getType().hasName("Curl_easy *")
and vconn_1481.(LocalVariable).getFunction() = func
and vdata_1479.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
