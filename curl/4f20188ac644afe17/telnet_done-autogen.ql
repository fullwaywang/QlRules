/**
 * @name curl-4f20188ac644afe17-telnet_done
 * @id cpp/curl/4f20188ac644afe17/telnet-done
 * @description curl-4f20188ac644afe17-telnet_done CVE-2022-43552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_1239, Variable vCurl_cfree, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="telnet"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1239
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="telnet"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1239
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vdata_1239, Variable vCurl_cfree
where
func_0(vdata_1239, vCurl_cfree, func)
and vdata_1239.getType().hasName("Curl_easy *")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vdata_1239.getParentScope+() = func
and not vCurl_cfree.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
