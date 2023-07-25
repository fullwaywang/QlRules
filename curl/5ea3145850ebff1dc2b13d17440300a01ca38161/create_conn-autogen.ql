/**
 * @name curl-5ea3145850ebff1dc2b13d17440300a01ca38161-create_conn
 * @id cpp/curl/5ea3145850ebff1dc2b13d17440300a01ca38161/create-conn
 * @description curl-5ea3145850ebff1dc2b13d17440300a01ca38161-lib/url.c-create_conn CVE-2021-22924
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Parameter vdata_3542, ExprStmt target_9, ValueFieldAccess target_10, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="issuercert_blob"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="blobs"
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
		and (func.getEntryPoint().(BlockStmt).getStmt(68)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(68).getFollowingStmt()=target_3)
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vdata_3542, ArrayExpr target_4) {
		target_4.getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="issuercert"
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
}

predicate func_5(Parameter vdata_3542, ArrayExpr target_5) {
		target_5.getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="issuercert"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_5.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
}

/*predicate func_6(Parameter vdata_3542, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="proxy_ssl"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
}

*/
/*predicate func_7(Parameter vdata_3542, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="ssl"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
}

*/
predicate func_8(Parameter vdata_3542, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="ssl"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
}

predicate func_9(Parameter vdata_3542, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cert_type"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
}

predicate func_10(Parameter vdata_3542, ValueFieldAccess target_10) {
		target_10.getTarget().getName()="proxy_ssl"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3542
}

from Function func, Parameter vdata_3542, ArrayExpr target_4, ArrayExpr target_5, ValueFieldAccess target_8, ExprStmt target_9, ValueFieldAccess target_10
where
not func_3(vdata_3542, target_9, target_10, func)
and func_4(vdata_3542, target_4)
and func_5(vdata_3542, target_5)
and func_8(vdata_3542, target_8)
and func_9(vdata_3542, target_9)
and func_10(vdata_3542, target_10)
and vdata_3542.getType().hasName("Curl_easy *")
and vdata_3542.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
