/**
 * @name curl-ba1dbd78e5f1e-Curl_smtp_escape_eob
 * @id cpp/curl/ba1dbd78e5f1e/Curl-smtp-escape-eob
 * @description curl-ba1dbd78e5f1e-Curl_smtp_escape_eob CVE-2018-0500
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vCurl_cmalloc) {
	exists(MulExpr target_0 |
		target_0.getValue()="32768"
		and target_0.getLeftOperand() instanceof Literal
		and target_0.getRightOperand().(Literal).getValue()="16384"
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cmalloc)
}

predicate func_1(Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).toString() = "{ ... }"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="2"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vCurl_cmalloc, Variable vdata_1555) {
	exists(MulExpr target_3 |
		target_3.getLeftOperand() instanceof Literal
		and target_3.getRightOperand().(ValueFieldAccess).getTarget().getName()="buffer_size"
		and target_3.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1555
		and target_3.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cmalloc)
}

from Function func, Variable vCurl_cmalloc, Variable vdata_1555
where
not func_0(vCurl_cmalloc)
and not func_1(func)
and func_2(func)
and func_3(vCurl_cmalloc, vdata_1555)
and vCurl_cmalloc.getType().hasName("curl_malloc_callback")
and vdata_1555.getType().hasName("Curl_easy *")
and not vCurl_cmalloc.getParentScope+() = func
and vdata_1555.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
