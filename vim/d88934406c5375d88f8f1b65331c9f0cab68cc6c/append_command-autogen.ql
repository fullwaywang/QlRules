/**
 * @name vim-d88934406c5375d88f8f1b65331c9f0cab68cc6c-append_command
 * @id cpp/vim/d88934406c5375d88f8f1b65331c9f0cab68cc6c/append-command
 * @description vim-d88934406c5375d88f8f1b65331c9f0cab68cc6c-src/ex_docmd.c-append_command CVE-2022-1616
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="7"
		and not target_0.getValue()="5"
		and target_0.getParent().(SubExpr).getParent().(LTExpr).getGreaterOperand() instanceof SubExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(AddExpr target_1 |
		target_1.getAnOperand() instanceof PointerArithmeticOperation
		and target_1.getAnOperand().(Literal).getValue()="5"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vs_3433, Variable vd_3434, Variable vIObuff, ConditionalExpr target_7, ExprStmt target_8, AddressOfExpr target_9, ExprStmt target_10, AddressOfExpr target_11) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vd_3434
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vIObuff
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("..(*)(..)")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vs_3433
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="1025"
		and target_2.getThen().(BreakStmt).toString() = "break;"
		and target_2.getElse() instanceof DoStmt
		and target_2.getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ExprCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ExprCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getOperand().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vd_3434, Variable vIObuff, PointerArithmeticOperation target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vd_3434
		and target_3.getRightOperand().(VariableAccess).getTarget()=vIObuff
}

predicate func_4(Function func, AddExpr target_4) {
		target_4.getValue()="1025"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vs_3433, Variable vd_3434, Variable vhas_mbyte, ConditionalExpr target_7, DoStmt target_5) {
		target_5.getCondition().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mb_copy_char")
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_3433
		and target_5.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vd_3434
		and target_5.getParent().(IfStmt).getCondition()=target_7
}

predicate func_6(Function func, SubExpr target_6) {
		target_6.getValue()="1018"
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vs_3433, ConditionalExpr target_7) {
		target_7.getThen().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vs_3433
		and target_7.getThen().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getThen().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="194"
		and target_7.getThen().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vs_3433
		and target_7.getThen().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_7.getThen().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="160"
		and target_7.getElse().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vs_3433
		and target_7.getElse().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="160"
}

predicate func_8(Variable vs_3433, ExprStmt target_8) {
		target_8.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_3433
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

predicate func_9(Variable vs_3433, AddressOfExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vs_3433
}

predicate func_10(Variable vd_3434, ExprStmt target_10) {
		target_10.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vd_3434
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="4"
}

predicate func_11(Variable vd_3434, AddressOfExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vd_3434
}

from Function func, Variable vs_3433, Variable vd_3434, Variable vIObuff, Variable vhas_mbyte, Literal target_0, PointerArithmeticOperation target_3, AddExpr target_4, DoStmt target_5, SubExpr target_6, ConditionalExpr target_7, ExprStmt target_8, AddressOfExpr target_9, ExprStmt target_10, AddressOfExpr target_11
where
func_0(func, target_0)
and not func_1(func)
and not func_2(vs_3433, vd_3434, vIObuff, target_7, target_8, target_9, target_10, target_11)
and func_3(vd_3434, vIObuff, target_3)
and func_4(func, target_4)
and func_5(vs_3433, vd_3434, vhas_mbyte, target_7, target_5)
and func_6(func, target_6)
and func_7(vs_3433, target_7)
and func_8(vs_3433, target_8)
and func_9(vs_3433, target_9)
and func_10(vd_3434, target_10)
and func_11(vd_3434, target_11)
and vs_3433.getType().hasName("char_u *")
and vd_3434.getType().hasName("char_u *")
and vIObuff.getType().hasName("char_u *")
and vhas_mbyte.getType().hasName("int")
and vs_3433.getParentScope+() = func
and vd_3434.getParentScope+() = func
and not vIObuff.getParentScope+() = func
and not vhas_mbyte.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
