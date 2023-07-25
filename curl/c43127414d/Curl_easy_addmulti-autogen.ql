/**
 * @name curl-c43127414d-Curl_easy_addmulti
 * @id cpp/curl/c43127414d/Curl-easy-addmulti
 * @description curl-c43127414d-lib/easy.c-Curl_easy_addmulti CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_552, Parameter vmulti_553, Function func, IfStmt target_0) {
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmulti_553
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_552
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Parameter vdata_552, Parameter vmulti_553, IfStmt target_0
where
func_0(vdata_552, vmulti_553, func, target_0)
and vdata_552.getType().hasName("SessionHandle *")
and vmulti_553.getType().hasName("void *")
and vdata_552.getParentScope+() = func
and vmulti_553.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
