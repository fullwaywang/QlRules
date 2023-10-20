/**
 * @name curl-c43127414d-Curl_setopt
 * @id cpp/curl/c43127414d/Curl-setopt
 * @description curl-c43127414d-lib/url.c-Curl_setopt CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vdata_651, PointerFieldAccess target_3, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="hostcachetype"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_651
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_hostcache_destroy")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_651
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Parameter vdata_651, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="hostcache"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_651
}

from Function func, Parameter vdata_651, IfStmt target_2, PointerFieldAccess target_3
where
func_2(vdata_651, target_3, target_2)
and func_3(vdata_651, target_3)
and vdata_651.getType().hasName("SessionHandle *")
and vdata_651.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
