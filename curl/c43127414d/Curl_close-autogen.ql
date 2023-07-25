/**
 * @name curl-c43127414d-Curl_close
 * @id cpp/curl/c43127414d/Curl-close
 * @description curl-c43127414d-lib/url.c-Curl_close CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_373, ExprStmt target_11, ValueFieldAccess target_12) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="multi_easy"
		and target_0.getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_373, ValueFieldAccess target_4, ExprStmt target_6) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("curl_multi_cleanup")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdata_373, VariableAccess target_2) {
		target_2.getTarget()=vdata_373
}

predicate func_3(Parameter vdata_373, VariableAccess target_3) {
		target_3.getTarget()=vdata_373
}

predicate func_4(Parameter vdata_373, ExprStmt target_11, ValueFieldAccess target_12, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="conn_cache"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_5(Parameter vdata_373, ValueFieldAccess target_4, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("close_connections")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_373
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_conncache_destroy")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_6(Parameter vdata_373, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("close_connections")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_373
}

/*predicate func_7(Parameter vdata_373, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("Curl_conncache_destroy")
		and target_7.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_7.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_7.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
}

*/
/*predicate func_8(Parameter vdata_373, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="conn_cache"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

*/
predicate func_9(Parameter vdata_373, IfStmt target_9) {
		target_9.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="hostcachetype"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dns"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_hostcache_destroy")
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_373
}

/*predicate func_10(Parameter vdata_373, FunctionCall target_10) {
		target_10.getTarget().hasName("Curl_hostcache_destroy")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vdata_373
}

*/
predicate func_11(Parameter vdata_373, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="magic"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_12(Parameter vdata_373, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="conn_cache"
		and target_12.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_373
}

from Function func, Parameter vdata_373, VariableAccess target_2, VariableAccess target_3, ValueFieldAccess target_4, IfStmt target_5, ExprStmt target_6, IfStmt target_9, ExprStmt target_11, ValueFieldAccess target_12
where
not func_0(vdata_373, target_11, target_12)
and not func_1(vdata_373, target_4, target_6)
and func_2(vdata_373, target_2)
and func_3(vdata_373, target_3)
and func_4(vdata_373, target_11, target_12, target_4)
and func_5(vdata_373, target_4, target_5)
and func_6(vdata_373, target_6)
and func_9(vdata_373, target_9)
and func_11(vdata_373, target_11)
and func_12(vdata_373, target_12)
and vdata_373.getType().hasName("SessionHandle *")
and vdata_373.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
