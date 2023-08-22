/**
 * @name curl-7f2a1df6f5fc598750b2c6f34465c8d924db28cc-Curl_ntlm_core_mk_ntlmv2_hash
 * @id cpp/curl/7f2a1df6f5fc598750b2c6f34465c8d924db28cc/Curl-ntlm-core-mk-ntlmv2-hash
 * @description curl-7f2a1df6f5fc598750b2c6f34465c8d924db28cc-lib/curl_ntlm_core.c-Curl_ntlm_core_mk_ntlmv2_hash CVE-2017-8816
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vuserlen_652, Parameter vdomlen_653, MulExpr target_3, ExprStmt target_7, ExprStmt target_8, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vuserlen_652
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="9223372036854775807"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdomlen_653
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="9223372036854775807"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vuserlen_652
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdomlen_653
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="9223372036854775807"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_3.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable videntity_len_658, VariableCall target_4, FunctionCall target_9, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=videntity_len_658
		and target_1.getExpr().(AssignExpr).getRValue() instanceof MulExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_4.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable videntity_659, NotExpr target_11, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=videntity_659
		and target_2.getExpr().(AssignExpr).getRValue() instanceof VariableCall
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2)
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vuserlen_652, Parameter vdomlen_653, MulExpr target_3) {
		target_3.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vuserlen_652
		and target_3.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdomlen_653
		and target_3.getRightOperand().(Literal).getValue()="2"
}

predicate func_4(Variable videntity_len_658, Variable vCurl_cmalloc, VariableCall target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vCurl_cmalloc
		and target_4.getArgument(0).(VariableAccess).getTarget()=videntity_len_658
}

predicate func_5(Function func, Initializer target_5) {
		target_5.getExpr() instanceof MulExpr
		and target_5.getExpr().getEnclosingFunction() = func
}

predicate func_6(Function func, Initializer target_6) {
		target_6.getExpr() instanceof VariableCall
		and target_6.getExpr().getEnclosingFunction() = func
}

predicate func_7(Parameter vuserlen_652, Variable videntity_659, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("ascii_uppercase_to_unicode_le")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=videntity_659
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vuserlen_652
}

predicate func_8(Parameter vuserlen_652, Parameter vdomlen_653, Variable videntity_659, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ascii_to_unicode_le")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=videntity_659
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vuserlen_652
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdomlen_653
}

predicate func_9(Variable videntity_len_658, FunctionCall target_9) {
		target_9.getTarget().hasName("curlx_uztoui")
		and target_9.getArgument(0).(VariableAccess).getTarget()=videntity_len_658
}

predicate func_11(Variable videntity_659, NotExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=videntity_659
}

from Function func, Parameter vuserlen_652, Parameter vdomlen_653, Variable videntity_len_658, Variable videntity_659, Variable vCurl_cmalloc, MulExpr target_3, VariableCall target_4, Initializer target_5, Initializer target_6, ExprStmt target_7, ExprStmt target_8, FunctionCall target_9, NotExpr target_11
where
not func_0(vuserlen_652, vdomlen_653, target_3, target_7, target_8, func)
and not func_1(videntity_len_658, target_4, target_9, func)
and not func_2(videntity_659, target_11, func)
and func_3(vuserlen_652, vdomlen_653, target_3)
and func_4(videntity_len_658, vCurl_cmalloc, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_7(vuserlen_652, videntity_659, target_7)
and func_8(vuserlen_652, vdomlen_653, videntity_659, target_8)
and func_9(videntity_len_658, target_9)
and func_11(videntity_659, target_11)
and vuserlen_652.getType().hasName("size_t")
and vdomlen_653.getType().hasName("size_t")
and videntity_len_658.getType().hasName("size_t")
and videntity_659.getType().hasName("unsigned char *")
and vCurl_cmalloc.getType().hasName("curl_malloc_callback")
and vuserlen_652.getFunction() = func
and vdomlen_653.getFunction() = func
and videntity_len_658.(LocalVariable).getFunction() = func
and videntity_659.(LocalVariable).getFunction() = func
and not vCurl_cmalloc.getParentScope+() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
