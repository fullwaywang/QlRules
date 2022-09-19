import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("char[6]")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("memset")
		and target_1.getType().hasName("void *")
		and target_1.getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_1.getArgument(1).(CharLiteral).getValue()="0"
		and target_1.getArgument(2).(SizeofExprOperator).getType().hasName("unsigned long")
		and target_1.getArgument(2).(SizeofExprOperator).getValue()="6"
		and target_1.getArgument(2).(SizeofExprOperator).getExprOperand().(VariableAccess).getType().hasName("char[6]")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vline, Parameter vlen) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getType().hasName("void *")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vline
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EQExpr).getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vlen
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="5"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="5"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="3")
}

predicate func_3(Parameter vresp) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vresp
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curlx_sltosi")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("strtol")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getType().hasName("long")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[6]")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="10")
}

from Function func, Parameter vline, Parameter vlen, Parameter vresp
where
not func_0(func)
and not func_1(func)
and not func_2(vline, vlen)
and not func_3(vresp)
and vline.getType().hasName("char *")
and vlen.getType().hasName("size_t")
and vresp.getType().hasName("int *")
and vline.getParentScope+() = func
and vlen.getParentScope+() = func
and vresp.getParentScope+() = func
select func, vline, vlen, vresp
