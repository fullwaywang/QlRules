/**
 * @name curl-f18af4f874-allocate_conn
 * @id cpp/curl/f18af4f874/allocate-conn
 * @description curl-f18af4f874-allocate_conn CVE-2022-27782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SizeofTypeOperator target_0 |
		target_0.getType() instanceof LongType
		and target_0.getValue()="1504"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vdata_1654, Variable vconn_1656, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1656
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1654
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vdata_1654, Variable vconn_1656, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proxy_ssl_config"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1656
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1654
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vdata_1654) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="set"
		and target_3.getQualifier().(VariableAccess).getTarget()=vdata_1654)
}

predicate func_5(Variable vconn_1656) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="ssl_config"
		and target_5.getQualifier().(VariableAccess).getTarget()=vconn_1656)
}

predicate func_6(Variable vconn_1656) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="proxy_ssl_config"
		and target_6.getQualifier().(VariableAccess).getTarget()=vconn_1656)
}

from Function func, Parameter vdata_1654, Variable vconn_1656
where
func_0(func)
and not func_1(vdata_1654, vconn_1656, func)
and not func_2(vdata_1654, vconn_1656, func)
and vdata_1654.getType().hasName("Curl_easy *")
and func_3(vdata_1654)
and vconn_1656.getType().hasName("connectdata *")
and func_5(vconn_1656)
and func_6(vconn_1656)
and vdata_1654.getParentScope+() = func
and vconn_1656.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
