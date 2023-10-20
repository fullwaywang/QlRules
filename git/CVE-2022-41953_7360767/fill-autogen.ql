/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-fill
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/fill
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-attr.c-fill CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vstack_1019, Variable vi_1023, ConditionalExpr target_9, ArrayExpr target_10) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vi_1023
		and target_1.getRValue().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vi_1023, BlockStmt target_11) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand() instanceof Literal
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vi_1023
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_2.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_11)
}

predicate func_4(Parameter vstack_1019, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="num_matches"
		and target_4.getQualifier().(VariableAccess).getTarget()=vstack_1019
}

predicate func_6(Parameter vstack_1019, Variable vi_1023, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vi_1023
		and target_6.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_6.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
		and target_6.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_7(Variable vi_1023, BlockStmt target_11, RelationalOperation target_7) {
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getLesserOperand() instanceof Literal
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vi_1023
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_7.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_11
}

predicate func_8(Parameter vstack_1019, Variable vi_1023, FunctionCall target_14, PostfixDecrExpr target_15, VariableAccess target_8) {
		target_8.getTarget()=vi_1023
		and target_8.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_8.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
		and target_8.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_15.getOperand().(VariableAccess).getLocation().isBefore(target_8.getLocation())
}

predicate func_9(Parameter vstack_1019, ConditionalExpr target_9) {
		target_9.getCondition().(PointerFieldAccess).getTarget().getName()="origin"
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
		and target_9.getThen().(PointerFieldAccess).getTarget().getName()="origin"
		and target_9.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
		and target_9.getElse().(StringLiteral).getValue()=""
}

predicate func_10(Parameter vstack_1019, Variable vi_1023, ArrayExpr target_10) {
		target_10.getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
		and target_10.getArrayOffset().(VariableAccess).getTarget()=vi_1023
}

predicate func_11(Parameter vstack_1019, BlockStmt target_11) {
		target_11.getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="is_macro"
		and target_11.getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_11.getStmt(0).(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("path_matches")
		and target_11.getStmt(0).(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="pat"
		and target_11.getStmt(0).(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_11.getStmt(0).(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="originlen"
		and target_11.getStmt(0).(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
		and target_11.getStmt(0).(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fill_one")
}

predicate func_14(Parameter vstack_1019, FunctionCall target_14) {
		target_14.getTarget().hasName("path_matches")
		and target_14.getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="pat"
		and target_14.getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_14.getArgument(5).(PointerFieldAccess).getTarget().getName()="originlen"
		and target_14.getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1019
}

predicate func_15(Variable vi_1023, PostfixDecrExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vi_1023
}

from Function func, Parameter vstack_1019, Variable vi_1023, PointerFieldAccess target_4, AssignExpr target_6, RelationalOperation target_7, VariableAccess target_8, ConditionalExpr target_9, ArrayExpr target_10, BlockStmt target_11, FunctionCall target_14, PostfixDecrExpr target_15
where
not func_1(vstack_1019, vi_1023, target_9, target_10)
and not func_2(vi_1023, target_11)
and func_4(vstack_1019, target_4)
and func_6(vstack_1019, vi_1023, target_6)
and func_7(vi_1023, target_11, target_7)
and func_8(vstack_1019, vi_1023, target_14, target_15, target_8)
and func_9(vstack_1019, target_9)
and func_10(vstack_1019, vi_1023, target_10)
and func_11(vstack_1019, target_11)
and func_14(vstack_1019, target_14)
and func_15(vi_1023, target_15)
and vstack_1019.getType().hasName("const attr_stack *")
and vi_1023.getType().hasName("int")
and vstack_1019.getParentScope+() = func
and vi_1023.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
