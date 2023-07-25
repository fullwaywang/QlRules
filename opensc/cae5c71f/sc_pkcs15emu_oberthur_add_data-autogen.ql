/**
 * @name opensc-cae5c71f-sc_pkcs15emu_oberthur_add_data
 * @id cpp/opensc/cae5c71f/sc-pkcs15emu-oberthur-add-data
 * @description opensc-cae5c71f-src/libopensc/pkcs15-oberthur.c-sc_pkcs15emu_oberthur_add_data CVE-2021-42781
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable void_len_915, BlockStmt target_2, RelationalOperation target_3, LogicalOrExpr target_4) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=void_len_915
		and target_0.getLesserOperand().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable void_len_915, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=void_len_915
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable void_len_915, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="6"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=void_len_915
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
}

predicate func_3(Variable void_len_915, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=void_len_915
}

predicate func_4(Variable void_len_915, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="6"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=void_len_915
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Variable void_len_915, VariableAccess target_1, BlockStmt target_2, RelationalOperation target_3, LogicalOrExpr target_4
where
not func_0(void_len_915, target_2, target_3, target_4)
and func_1(void_len_915, target_2, target_1)
and func_2(void_len_915, target_2)
and func_3(void_len_915, target_3)
and func_4(void_len_915, target_4)
and void_len_915.getType().hasName("size_t")
and void_len_915.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
