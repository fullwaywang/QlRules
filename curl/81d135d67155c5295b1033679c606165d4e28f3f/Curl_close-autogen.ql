/**
 * @name curl-81d135d67155c5295b1033679c606165d4e28f3f-Curl_close
 * @id cpp/curl/81d135d67155c5295b1033679c606165d4e28f3f/Curl-close
 * @description curl-81d135d67155c5295b1033679c606165d4e28f3f-lib/url.c-Curl_close CVE-2018-16840
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_319, PointerFieldAccess target_2, IfStmt target_3, ExprStmt target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_319
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_319, PointerFieldAccess target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("curl_multi_cleanup")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_319
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vdata_319, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="multi_easy"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdata_319
}

predicate func_3(Parameter vdata_319, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_319
		and target_3.getThen() instanceof ExprStmt
}

from Function func, Parameter vdata_319, ExprStmt target_1, PointerFieldAccess target_2, IfStmt target_3
where
not func_0(vdata_319, target_2, target_3, target_1)
and func_1(vdata_319, target_2, target_1)
and func_2(vdata_319, target_2)
and func_3(vdata_319, target_3)
and vdata_319.getType().hasName("Curl_easy *")
and vdata_319.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
