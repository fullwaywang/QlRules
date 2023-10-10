/**
 * @name curl-a64e3e59938abd7d6-Curl_vsetopt
 * @id cpp/curl/a64e3e59938abd7d6/Curl-vsetopt
 * @description curl-a64e3e59938abd7d6-Curl_vsetopt CVE-2022-32221
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voption_238, Parameter vdata_238) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="upload"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_238
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=voption_238)
}

predicate func_1(Parameter vdata_238) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="set"
		and target_1.getQualifier().(VariableAccess).getTarget()=vdata_238)
}

from Function func, Parameter voption_238, Parameter vdata_238
where
not func_0(voption_238, vdata_238)
and voption_238.getType().hasName("CURLoption")
and vdata_238.getType().hasName("Curl_easy *")
and func_1(vdata_238)
and voption_238.getParentScope+() = func
and vdata_238.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
