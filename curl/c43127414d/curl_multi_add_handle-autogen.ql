/**
 * @name curl-c43127414d-curl_multi_add_handle
 * @id cpp/curl/c43127414d/curl-multi-add-handle
 * @description curl-c43127414d-lib/multi.c-curl_multi_add_handle CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable veasy_432, FunctionCall target_0) {
		target_0.getTarget().hasName("multistate")
		and not target_0.getTarget().hasName("mstate")
		and target_0.getArgument(0).(VariableAccess).getTarget()=veasy_432
}

predicate func_3(Variable veasy_432, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="easy_handle"
		and target_3.getQualifier().(VariableAccess).getTarget()=veasy_432
}

predicate func_4(Variable veasy_432, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="hostcachetype"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_432
}

predicate func_5(Variable veasy_432, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="easy_handle"
		and target_5.getQualifier().(VariableAccess).getTarget()=veasy_432
}

predicate func_6(Variable veasy_432, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="hostcache"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_432
}

predicate func_7(Variable veasy_432, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="easy_handle"
		and target_7.getQualifier().(VariableAccess).getTarget()=veasy_432
}

predicate func_8(Variable veasy_432, Function func, IfStmt target_8) {
		target_8.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="hostcache"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_432
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof ValueFieldAccess
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_hash_destroy")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hostcache"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="hostcachetype"
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof EnumConstantAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

/*predicate func_9(Variable veasy_432, LogicalAndExpr target_13, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("Curl_hash_destroy")
		and target_9.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hostcache"
		and target_9.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_9.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_9.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_432
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

*/
/*predicate func_10(LogicalAndExpr target_13, Function func, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_10.getEnclosingFunction() = func
}

*/
predicate func_11(Variable veasy_432, Function func, IfStmt target_11) {
		target_11.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_432
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_conncache_destroy")
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

/*predicate func_12(Variable veasy_432, LogicalAndExpr target_14, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("Curl_conncache_destroy")
		and target_12.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_12.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_12.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_12.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_432
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

*/
predicate func_13(LogicalAndExpr target_13) {
		target_13.getAnOperand() instanceof ValueFieldAccess
		and target_13.getAnOperand() instanceof EqualityOperation
}

predicate func_14(LogicalAndExpr target_14) {
		target_14.getAnOperand() instanceof ValueFieldAccess
		and target_14.getAnOperand() instanceof EqualityOperation
}

from Function func, Variable veasy_432, FunctionCall target_0, PointerFieldAccess target_3, ValueFieldAccess target_4, PointerFieldAccess target_5, ValueFieldAccess target_6, PointerFieldAccess target_7, IfStmt target_8, IfStmt target_11, LogicalAndExpr target_13, LogicalAndExpr target_14
where
func_0(veasy_432, target_0)
and func_3(veasy_432, target_3)
and func_4(veasy_432, target_4)
and func_5(veasy_432, target_5)
and func_6(veasy_432, target_6)
and func_7(veasy_432, target_7)
and func_8(veasy_432, func, target_8)
and func_11(veasy_432, func, target_11)
and func_13(target_13)
and func_14(target_14)
and veasy_432.getType().hasName("Curl_one_easy *")
and veasy_432.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
