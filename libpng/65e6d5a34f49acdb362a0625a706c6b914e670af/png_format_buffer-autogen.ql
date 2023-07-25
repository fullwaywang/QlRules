/**
 * @name libpng-65e6d5a34f49acdb362a0625a706c6b914e670af-png_format_buffer
 * @id cpp/libpng/65e6d5a34f49acdb362a0625a706c6b914e670af/png-format-buffer
 * @description libpng-65e6d5a34f49acdb362a0625a706c6b914e670af-pngerror.c-png_format_buffer CVE-2011-2501
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable viout_165, VariableAccess target_0) {
		target_0.getTarget()=viout_165
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="64"
		and not target_1.getValue()="0"
		and target_1.getParent().(AddExpr).getParent().(SubExpr).getLeftOperand() instanceof AddExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable viin_165, ArrayExpr target_15) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=viin_165
		and target_2.getRValue().(Literal).getValue()="0"
		and target_15.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getLValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter verror_message_163, Variable viout_165, Variable viin_165, Parameter vbuffer_162, EqualityOperation target_16, PointerArithmeticOperation target_17) {
	exists(WhileStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="63"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=verror_message_163
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=viin_165
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_3.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_162
		and target_3.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=viout_165
		and target_3.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=verror_message_163
		and target_3.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=viin_165
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_17.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Variable viout_165, Parameter vbuffer_162, PointerArithmeticOperation target_17) {
	exists(PostfixIncrExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=viout_165
		and target_4.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_162
		and target_17.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_5(Parameter verror_message_163, Variable viin_165, Parameter vbuffer_162) {
	exists(ArrayExpr target_5 |
		target_5.getArrayBase().(VariableAccess).getTarget()=verror_message_163
		and target_5.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=viin_165
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_162
		and target_5.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset() instanceof SubExpr)
}

*/
predicate func_6(Variable viout_165, Parameter vbuffer_162, ExprStmt target_21, ExprStmt target_22) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_162
		and target_6.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=viout_165
		and target_6.getRValue() instanceof CharLiteral
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_6.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vbuffer_162, VariableAccess target_7) {
		target_7.getTarget()=vbuffer_162
}

predicate func_8(Variable viout_165, VariableAccess target_8) {
		target_8.getTarget()=viout_165
}

predicate func_11(Parameter verror_message_163, VariableAccess target_11) {
		target_11.getTarget()=verror_message_163
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_13(Parameter verror_message_163, Variable viout_165, Parameter vbuffer_162, FunctionCall target_13) {
		target_13.getTarget().hasName("memcpy")
		and target_13.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_162
		and target_13.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=viout_165
		and target_13.getArgument(1).(VariableAccess).getTarget()=verror_message_163
		and target_13.getArgument(2) instanceof Literal
}

predicate func_14(Variable viout_165, Parameter vbuffer_162, SubExpr target_14) {
		target_14.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=viout_165
		and target_14.getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_14.getRightOperand() instanceof Literal
		and target_14.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_162
}

predicate func_15(Variable viin_165, ArrayExpr target_15) {
		target_15.getArrayBase().(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_15.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=viin_165
}

predicate func_16(Parameter verror_message_163, EqualityOperation target_16) {
		target_16.getAnOperand().(VariableAccess).getTarget()=verror_message_163
		and target_16.getAnOperand().(Literal).getValue()="0"
}

predicate func_17(Variable viout_165, Parameter vbuffer_162, PointerArithmeticOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vbuffer_162
		and target_17.getAnOperand().(VariableAccess).getTarget()=viout_165
}

predicate func_21(Variable viout_165, Parameter vbuffer_162, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_162
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=viout_165
		and target_21.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="32"
}

predicate func_22(Parameter vbuffer_162, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_162
		and target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset() instanceof SubExpr
		and target_22.getExpr().(AssignExpr).getRValue() instanceof CharLiteral
}

from Function func, Parameter verror_message_163, Variable viout_165, Variable viin_165, Parameter vbuffer_162, VariableAccess target_0, Literal target_1, VariableAccess target_7, VariableAccess target_8, VariableAccess target_11, FunctionCall target_13, SubExpr target_14, ArrayExpr target_15, EqualityOperation target_16, PointerArithmeticOperation target_17, ExprStmt target_21, ExprStmt target_22
where
func_0(viout_165, target_0)
and func_1(func, target_1)
and not func_2(viin_165, target_15)
and not func_3(verror_message_163, viout_165, viin_165, vbuffer_162, target_16, target_17)
and not func_6(viout_165, vbuffer_162, target_21, target_22)
and func_7(vbuffer_162, target_7)
and func_8(viout_165, target_8)
and func_11(verror_message_163, target_11)
and func_13(verror_message_163, viout_165, vbuffer_162, target_13)
and func_14(viout_165, vbuffer_162, target_14)
and func_15(viin_165, target_15)
and func_16(verror_message_163, target_16)
and func_17(viout_165, vbuffer_162, target_17)
and func_21(viout_165, vbuffer_162, target_21)
and func_22(vbuffer_162, target_22)
and verror_message_163.getType().hasName("png_const_charp")
and viout_165.getType().hasName("int")
and viin_165.getType().hasName("int")
and vbuffer_162.getType().hasName("png_charp")
and verror_message_163.getParentScope+() = func
and viout_165.getParentScope+() = func
and viin_165.getParentScope+() = func
and vbuffer_162.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
