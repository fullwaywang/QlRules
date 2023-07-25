/**
 * @name curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-Curl_pretransfer
 * @id cpp/curl/076a2f629119222aeeb50f5a03bf9f9052fabb9a/Curl-pretransfer
 * @description curl-076a2f629119222aeeb50f5a03bf9f9052fabb9a-lib/transfer.c-Curl_pretransfer CVE-2023-23914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_1330, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("Curl_hsts_loadfiles")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_1330
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_1330, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_loadhostpairs")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_1330
}

predicate func_2(Parameter vdata_1330, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="allow_port"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1330
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vdata_1330, ExprStmt target_1, ExprStmt target_2
where
not func_0(vdata_1330, target_1, target_2, func)
and func_1(vdata_1330, target_1)
and func_2(vdata_1330, target_2)
and vdata_1330.getType().hasName("Curl_easy *")
and vdata_1330.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
