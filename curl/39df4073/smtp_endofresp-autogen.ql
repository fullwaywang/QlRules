/**
 * @name curl-39df4073-smtp_endofresp
 * @id cpp/curl/39df4073/smtp-endofresp
 * @description curl-39df4073-lib/smtp.c-smtp_endofresp CVE-2019-3823
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("memset")
		and target_0.getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_0.getArgument(1).(CharLiteral).getValue()="0"
		and target_0.getArgument(2).(SizeofExprOperator).getValue()="6"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vline_195, Parameter vlen_195, LogicalOrExpr target_5, LogicalAndExpr target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vline_195
		and target_1.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_195
		and target_1.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
		and target_1.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="5"
		and target_1.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="3"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vresp_196, LogicalOrExpr target_5, EqualityOperation target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vresp_196
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curlx_sltosi")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("strtol")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vline_195, VariableAccess target_4) {
		target_4.getTarget()=vline_195
		and target_4.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("strtol")
		and target_4.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="10"
}

predicate func_5(Parameter vline_195, Parameter vlen_195, LogicalOrExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_195
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_195
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
}

predicate func_6(Parameter vline_195, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_195
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("smtp_conn *")
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("smtp_conn *")
}

predicate func_7(Parameter vresp_196, EqualityOperation target_7) {
		target_7.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vresp_196
		and target_7.getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vline_195, Parameter vlen_195, Parameter vresp_196, VariableAccess target_4, LogicalOrExpr target_5, LogicalAndExpr target_6, EqualityOperation target_7
where
not func_0(func)
and not func_1(vline_195, vlen_195, target_5, target_6)
and not func_2(vresp_196, target_5, target_7)
and func_4(vline_195, target_4)
and func_5(vline_195, vlen_195, target_5)
and func_6(vline_195, target_6)
and func_7(vresp_196, target_7)
and vline_195.getType().hasName("char *")
and vlen_195.getType().hasName("size_t")
and vresp_196.getType().hasName("int *")
and vline_195.getFunction() = func
and vlen_195.getFunction() = func
and vresp_196.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
