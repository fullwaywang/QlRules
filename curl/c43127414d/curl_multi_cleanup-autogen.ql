/**
 * @name curl-c43127414d-curl_multi_cleanup
 * @id cpp/curl/c43127414d/curl-multi-cleanup
 * @description curl-c43127414d-lib/multi.c-curl_multi_cleanup CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vmulti_1890, LogicalAndExpr target_3, ExprStmt target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hostcache"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="closure_handle"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_1890
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hostcache"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_1890
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmulti_1890, LogicalAndExpr target_3, ExprStmt target_5) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("Curl_hostcache_clean")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="closure_handle"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_1890
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vmulti_1890, LogicalAndExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vmulti_1890
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_1890
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="764702"
}

predicate func_4(Variable vmulti_1890, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("close_all_connections")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmulti_1890
}

predicate func_5(Variable vmulti_1890, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("Curl_close")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="closure_handle"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_1890
}

from Function func, Variable vmulti_1890, LogicalAndExpr target_3, ExprStmt target_4, ExprStmt target_5
where
not func_1(vmulti_1890, target_3, target_4)
and not func_2(vmulti_1890, target_3, target_5)
and func_3(vmulti_1890, target_3)
and func_4(vmulti_1890, target_4)
and func_5(vmulti_1890, target_5)
and vmulti_1890.getType().hasName("Curl_multi *")
and vmulti_1890.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
