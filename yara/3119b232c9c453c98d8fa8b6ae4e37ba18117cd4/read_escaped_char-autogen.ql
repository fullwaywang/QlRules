/**
 * @name yara-3119b232c9c453c98d8fa8b6ae4e37ba18117cd4-read_escaped_char
 * @id cpp/yara/3119b232c9c453c98d8fa8b6ae4e37ba18117cd4/read-escaped-char
 * @description yara-3119b232c9c453c98d8fa8b6ae4e37ba18117cd4-libyara/re_lexer.c-read_escaped_char CVE-2016-10210
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(UnaryMinusExpr).getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vtext_2566, ReturnStmt target_11, ExprStmt target_12) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtext_2566
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_11
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vtext_2566, ReturnStmt target_14, ExprStmt target_12) {
	exists(ArrayExpr target_2 |
		target_2.getArrayBase().(VariableAccess).getTarget()=vtext_2566
		and target_2.getArrayOffset() instanceof Literal
		and target_2.getParent().(EQExpr).getAnOperand() instanceof ArrayExpr
		and target_2.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_14
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getArrayBase().(VariableAccess).getLocation()))
}

*/
predicate func_3(ReturnStmt target_14, Function func) {
	exists(NotExpr target_3 |
		target_3.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_3.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset() instanceof ArrayExpr
		and target_3.getParent().(IfStmt).getThen()=target_14
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(ReturnStmt target_16, Function func) {
	exists(NotExpr target_4 |
		target_4.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_4.getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset() instanceof ArrayExpr
		and target_4.getParent().(IfStmt).getThen()=target_16
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vtext_2566, ReturnStmt target_11, EqualityOperation target_5) {
		target_5.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtext_2566
		and target_5.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_5.getParent().(IfStmt).getThen()=target_11
}

predicate func_6(Variable vtext_2566, ReturnStmt target_14, ArrayExpr target_6) {
		target_6.getArrayBase().(VariableAccess).getTarget()=vtext_2566
		and target_6.getArrayOffset().(Literal).getValue()="2"
		and target_6.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_6.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_14
}

predicate func_7(Variable vtext_2566, ReturnStmt target_16, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vtext_2566
		and target_7.getArrayOffset().(Literal).getValue()="3"
		and target_7.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_7.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_9(ReturnStmt target_14, Function func, UnaryMinusExpr target_9) {
		target_9.getValue()="-1"
		and target_9.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_14
		and target_9.getEnclosingFunction() = func
}

predicate func_10(ReturnStmt target_16, Function func, EqualityOperation target_10) {
		target_10.getAnOperand() instanceof ArrayExpr
		and target_10.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_10.getParent().(IfStmt).getThen()=target_16
		and target_10.getEnclosingFunction() = func
}

predicate func_11(ReturnStmt target_11) {
		target_11.getExpr().(Literal).getValue()="0"
}

predicate func_12(Variable vtext_2566, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtext_2566
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("input")
}

predicate func_14(ReturnStmt target_14) {
		target_14.getExpr().(Literal).getValue()="0"
}

predicate func_16(ReturnStmt target_16) {
		target_16.getExpr().(Literal).getValue()="0"
}

from Function func, Variable vtext_2566, Literal target_0, EqualityOperation target_5, ArrayExpr target_6, ArrayExpr target_7, UnaryMinusExpr target_9, EqualityOperation target_10, ReturnStmt target_11, ExprStmt target_12, ReturnStmt target_14, ReturnStmt target_16
where
func_0(func, target_0)
and not func_1(vtext_2566, target_11, target_12)
and not func_3(target_14, func)
and not func_4(target_16, func)
and func_5(vtext_2566, target_11, target_5)
and func_6(vtext_2566, target_14, target_6)
and func_7(vtext_2566, target_16, target_7)
and func_9(target_14, func, target_9)
and func_10(target_16, func, target_10)
and func_11(target_11)
and func_12(vtext_2566, target_12)
and func_14(target_14)
and func_16(target_16)
and vtext_2566.getType().hasName("char[4]")
and vtext_2566.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
