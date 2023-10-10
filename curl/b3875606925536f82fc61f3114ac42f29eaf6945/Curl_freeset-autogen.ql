/**
 * @name curl-b3875606925536f82fc61f3114ac42f29eaf6945-Curl_freeset
 * @id cpp/curl/b3875606925536f82fc61f3114ac42f29eaf6945/Curl-freeset
 * @description curl-b3875606925536f82fc61f3114ac42f29eaf6945-lib/url.c-Curl_freeset CVE-2014-3707
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vi_272, Variable vCurl_cfree, Parameter vdata_269, DoStmt target_1) {
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_269
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_272
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vi_272, Variable vCurl_cfree, Parameter vdata_269, DoStmt target_1
where
func_1(vi_272, vCurl_cfree, vdata_269, target_1)
and vi_272.getType().hasName("dupstring")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vdata_269.getType().hasName("SessionHandle *")
and vi_272.getParentScope+() = func
and not vCurl_cfree.getParentScope+() = func
and vdata_269.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
