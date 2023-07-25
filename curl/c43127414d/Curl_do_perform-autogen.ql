/**
 * @name curl-c43127414d-Curl_do_perform
 * @id cpp/curl/c43127414d/Curl-do-perform
 * @description curl-c43127414d-lib/transfer.c-Curl_do_perform CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_2063, Function func, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2063
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Parameter vdata_2063, ExprStmt target_0
where
func_0(vdata_2063, func, target_0)
and vdata_2063.getType().hasName("SessionHandle *")
and vdata_2063.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
