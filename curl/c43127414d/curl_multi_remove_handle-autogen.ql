/**
 * @name curl-c43127414d-curl_multi_remove_handle
 * @id cpp/curl/c43127414d/curl-multi-remove-handle
 * @description curl-c43127414d-lib/multi.c-curl_multi_remove_handle CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable veasy_616, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="easy_handle"
		and target_1.getQualifier().(VariableAccess).getTarget()=veasy_616
}

predicate func_2(Variable veasy_616, EqualityOperation target_13, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_3(Variable vmulti_615, Variable veasy_616, Variable veasy_owns_conn_632, EqualityOperation target_14, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="num_easy"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_615
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=veasy_owns_conn_632
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_hostcache_destroy")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hostcache"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_615
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

/*predicate func_4(Variable veasy_616, Variable veasy_owns_conn_632, EqualityOperation target_15, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=veasy_owns_conn_632
		and target_4.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_resolv_unlock")
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

*/
/*predicate func_5(VariableAccess target_16, Function func, DoStmt target_5) {
		target_5.getCondition().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_5.getEnclosingFunction() = func
}

*/
/*predicate func_6(Variable veasy_616, VariableAccess target_16, IfStmt target_6) {
		target_6.getCondition().(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_resolv_unlock")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

*/
/*predicate func_7(Variable veasy_616, PointerFieldAccess target_17, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("Curl_resolv_unlock")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_7.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_7.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_7.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
/*predicate func_8(Variable veasy_616, PointerFieldAccess target_17, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dns_entry"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
/*predicate func_9(Variable veasy_616, EqualityOperation target_15, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("Curl_hostcache_destroy")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

*/
/*predicate func_10(Variable vmulti_615, EqualityOperation target_15, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hostcache"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_615
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

*/
predicate func_11(Variable veasy_616, VariableAccess target_18, IfStmt target_11) {
		target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_11.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect"
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

/*predicate func_12(Variable veasy_616, EqualityOperation target_13, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

*/
predicate func_13(EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_13.getAnOperand() instanceof EnumConstantAccess
}

predicate func_14(Variable veasy_616, EqualityOperation target_14) {
		target_14.getAnOperand().(ValueFieldAccess).getTarget().getName()="hostcachetype"
		and target_14.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_14.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="easy_handle"
		and target_14.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
		and target_14.getAnOperand() instanceof EnumConstantAccess
}

predicate func_15(Variable vmulti_615, EqualityOperation target_15) {
		target_15.getAnOperand().(PointerFieldAccess).getTarget().getName()="num_easy"
		and target_15.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_615
		and target_15.getAnOperand() instanceof Literal
}

predicate func_16(Variable veasy_owns_conn_632, VariableAccess target_16) {
		target_16.getTarget()=veasy_owns_conn_632
}

predicate func_17(Variable veasy_616, PointerFieldAccess target_17) {
		target_17.getTarget().getName()="dns_entry"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veasy_616
}

predicate func_18(Variable veasy_616, VariableAccess target_18) {
		target_18.getTarget()=veasy_616
}

from Function func, Variable vmulti_615, Variable veasy_616, Variable veasy_owns_conn_632, PointerFieldAccess target_1, ExprStmt target_2, IfStmt target_3, IfStmt target_11, EqualityOperation target_13, EqualityOperation target_14, EqualityOperation target_15, VariableAccess target_16, PointerFieldAccess target_17, VariableAccess target_18
where
func_1(veasy_616, target_1)
and func_2(veasy_616, target_13, target_2)
and func_3(vmulti_615, veasy_616, veasy_owns_conn_632, target_14, target_3)
and func_11(veasy_616, target_18, target_11)
and func_13(target_13)
and func_14(veasy_616, target_14)
and func_15(vmulti_615, target_15)
and func_16(veasy_owns_conn_632, target_16)
and func_17(veasy_616, target_17)
and func_18(veasy_616, target_18)
and vmulti_615.getType().hasName("Curl_multi *")
and veasy_616.getType().hasName("Curl_one_easy *")
and veasy_owns_conn_632.getType().hasName("bool")
and vmulti_615.getParentScope+() = func
and veasy_616.getParentScope+() = func
and veasy_owns_conn_632.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
