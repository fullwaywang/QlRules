/**
 * @name curl-39df4073e5413fcdbb5a38da0c1ce6f1c0ceb484-smtp_endofresp
 * @id cpp/curl/39df4073e5413fcdbb5a38da0c1ce6f1c0ceb484/smtp-endofresp
 * @description curl-39df4073e5413fcdbb5a38da0c1ce6f1c0ceb484-smtp_endofresp CVE-2019-3823
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vline_195, Parameter vlen_195) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_195
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_195
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="5")
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("memset")
		and target_1.getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_1.getArgument(1).(CharLiteral).getValue()="0"
		and target_1.getArgument(2).(SizeofExprOperator).getValue()="6"
		and target_1.getArgument(2).(SizeofExprOperator).getExprOperand().(VariableAccess).getType().hasName("char[6]")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vline_195, Parameter vlen_195) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vline_195
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_195
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="5"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="3"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_195
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_195
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="5")
}

predicate func_3(Parameter vline_195, Parameter vlen_195, Parameter vresp_196) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vresp_196
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curlx_sltosi")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("strtol")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_195
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_195
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="5")
}

predicate func_6(Parameter vline_195, Parameter vlen_195, Parameter vresp_196, Variable vresult_199) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vlen_195
		and target_6.getAnOperand().(Literal).getValue()="5"
		and target_6.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_195
		and target_6.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_6.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_199
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vresp_196
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curlx_sltosi")
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("strtol")
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_195
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vresp_196
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vresp_196
		and target_6.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vline_195, Parameter vlen_195, Parameter vresp_196, Variable vresult_199
where
not func_0(vline_195, vlen_195)
and not func_1(func)
and not func_2(vline_195, vlen_195)
and not func_3(vline_195, vlen_195, vresp_196)
and vline_195.getType().hasName("char *")
and vlen_195.getType().hasName("size_t")
and func_6(vline_195, vlen_195, vresp_196, vresult_199)
and vresp_196.getType().hasName("int *")
and vresult_199.getType().hasName("bool")
and vline_195.getParentScope+() = func
and vlen_195.getParentScope+() = func
and vresp_196.getParentScope+() = func
and vresult_199.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
