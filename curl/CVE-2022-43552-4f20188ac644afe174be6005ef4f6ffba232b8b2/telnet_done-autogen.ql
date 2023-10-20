/**
 * @name curl-4f20188ac644afe174be6005ef4f6ffba232b8b2-telnet_done
 * @id cpp/curl/4f20188ac644afe174be6005ef4f6ffba232b8b2/telnet-done
 * @description curl-4f20188ac644afe174be6005ef4f6ffba232b8b2-lib/telnet.c-telnet_done CVE-2022-43552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vCurl_cfree, Function func, DoStmt target_0) {
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="telnet"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="telnet"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

/*predicate func_1(Parameter vdata_1239, Variable vCurl_cfree, ExprStmt target_1) {
		target_1.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_1.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="telnet"
		and target_1.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_1.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_1.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1239
}

*/
/*predicate func_2(Parameter vdata_1239, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="telnet"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1239
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

*/
from Function func, Parameter vdata_1239, Variable vCurl_cfree, DoStmt target_0
where
func_0(vCurl_cfree, func, target_0)
and vdata_1239.getType().hasName("Curl_easy *")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vdata_1239.getFunction() = func
and not vCurl_cfree.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
