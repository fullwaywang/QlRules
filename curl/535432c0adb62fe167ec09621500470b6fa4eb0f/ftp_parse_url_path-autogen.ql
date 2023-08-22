/**
 * @name curl-535432c0adb62fe167ec09621500470b6fa4eb0f-ftp_parse_url_path
 * @id cpp/curl/535432c0adb62fe167ec09621500470b6fa4eb0f/ftp-parse-url-path
 * @description curl-535432c0adb62fe167ec09621500470b6fa4eb0f-lib/ftp.c-ftp_parse_url_path CVE-2018-1000120
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_urldecode")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("connectdata *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(StringLiteral).getValue()="/"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="dirs"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ftp_conn *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="1"
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("Curl_urldecode")
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("connectdata *")
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="path"
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Curl_easy *")
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_1.getEnclosingFunction() = func
}

from Function func, Literal target_0, Literal target_1
where
func_0(func, target_0)
and func_1(func, target_1)
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
