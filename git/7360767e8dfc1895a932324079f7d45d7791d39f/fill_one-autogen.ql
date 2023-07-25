/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-fill_one
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/fill-one
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-attr.c-fill_one CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter va_1000, Variable vi_1002, ArrayExpr target_12) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vi_1002
		and target_1.getRValue().(PointerFieldAccess).getTarget().getName()="num_attr"
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vi_1002, BlockStmt target_13) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vi_1002
		and target_2.getLesserOperand() instanceof Literal
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_2.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_13)
}

predicate func_3(Parameter va_1000, Variable vi_1002, PostfixDecrExpr target_16, ArrayExpr target_12) {
	exists(SubExpr target_3 |
		target_3.getLeftOperand().(VariableAccess).getTarget()=vi_1002
		and target_3.getRightOperand() instanceof Literal
		and target_3.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_16.getOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation())
		and target_3.getLeftOperand().(VariableAccess).getLocation().isBefore(target_12.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_4(Parameter va_1000, Variable vi_1002, ArrayExpr target_12, ArrayExpr target_17) {
	exists(SubExpr target_4 |
		target_4.getLeftOperand().(VariableAccess).getTarget()=vi_1002
		and target_4.getRightOperand().(Literal).getValue()="1"
		and target_4.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_12.getArrayOffset().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(VariableAccess).getLocation())
		and target_4.getLeftOperand().(VariableAccess).getLocation().isBefore(target_17.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_5(Parameter va_1000, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="num_attr"
		and target_5.getQualifier().(VariableAccess).getTarget()=va_1000
}

predicate func_8(Parameter va_1000, Variable vi_1002, AssignExpr target_8) {
		target_8.getLValue().(VariableAccess).getTarget()=vi_1002
		and target_8.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_attr"
		and target_8.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_8.getRValue().(SubExpr).getRightOperand() instanceof Literal
}

predicate func_9(Variable vi_1002, BlockStmt target_13, RelationalOperation target_9) {
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vi_1002
		and target_9.getLesserOperand() instanceof Literal
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_9.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_13
}

predicate func_10(Parameter va_1000, Variable vi_1002, ArrayExpr target_17, VariableAccess target_10) {
		target_10.getTarget()=vi_1002
		and target_10.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="state"
		and target_10.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_10.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_11(Parameter va_1000, Variable vi_1002, ArrayExpr target_12, VariableAccess target_11) {
		target_11.getTarget()=vi_1002
		and target_11.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="state"
		and target_11.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(Parameter va_1000, Variable vi_1002, ArrayExpr target_12) {
		target_12.getArrayBase().(PointerFieldAccess).getTarget().getName()="state"
		and target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_12.getArrayOffset().(VariableAccess).getTarget()=vi_1002
}

predicate func_13(BlockStmt target_13) {
		target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("macroexpand_one")
		and target_13.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="attr_nr"
}

predicate func_16(Variable vi_1002, PostfixDecrExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vi_1002
}

predicate func_17(Parameter va_1000, Variable vi_1002, ArrayExpr target_17) {
		target_17.getArrayBase().(PointerFieldAccess).getTarget().getName()="state"
		and target_17.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_1000
		and target_17.getArrayOffset().(VariableAccess).getTarget()=vi_1002
}

from Function func, Parameter va_1000, Variable vi_1002, PointerFieldAccess target_5, AssignExpr target_8, RelationalOperation target_9, VariableAccess target_10, VariableAccess target_11, ArrayExpr target_12, BlockStmt target_13, PostfixDecrExpr target_16, ArrayExpr target_17
where
not func_1(va_1000, vi_1002, target_12)
and not func_2(vi_1002, target_13)
and not func_3(va_1000, vi_1002, target_16, target_12)
and not func_4(va_1000, vi_1002, target_12, target_17)
and func_5(va_1000, target_5)
and func_8(va_1000, vi_1002, target_8)
and func_9(vi_1002, target_13, target_9)
and func_10(va_1000, vi_1002, target_17, target_10)
and func_11(va_1000, vi_1002, target_12, target_11)
and func_12(va_1000, vi_1002, target_12)
and func_13(target_13)
and func_16(vi_1002, target_16)
and func_17(va_1000, vi_1002, target_17)
and va_1000.getType().hasName("const match_attr *")
and vi_1002.getType().hasName("int")
and va_1000.getParentScope+() = func
and vi_1002.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
