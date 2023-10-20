/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-determine_macros
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/determine-macros
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-attr.c-determine_macros CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vstack_1055, Variable vi_1058, AssignExpr target_10, ArrayExpr target_11) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vi_1058
		and target_2.getRValue().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_2.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1055
		and target_10.getLValue().(VariableAccess).getLocation().isBefore(target_2.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vi_1058, BlockStmt target_12, RelationalOperation target_8) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vi_1058
		and target_3.getLesserOperand() instanceof Literal
		and target_3.getParent().(ForStmt).getStmt()=target_12
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vstack_1055, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="num_matches"
		and target_5.getQualifier().(VariableAccess).getTarget()=vstack_1055
}

predicate func_7(Parameter vstack_1055, Variable vi_1058, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vi_1058
		and target_7.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_7.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1055
		and target_7.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_8(Variable vi_1058, BlockStmt target_12, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(VariableAccess).getTarget()=vi_1058
		and target_8.getLesserOperand() instanceof Literal
		and target_8.getParent().(ForStmt).getStmt()=target_12
}

predicate func_9(Parameter vstack_1055, Variable vi_1058, PostfixDecrExpr target_14, VariableAccess target_9) {
		target_9.getTarget()=vi_1058
		and target_9.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_9.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1055
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_9.getLocation())
}

predicate func_10(Parameter vstack_1055, AssignExpr target_10) {
		target_10.getLValue().(VariableAccess).getTarget()=vstack_1055
		and target_10.getRValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_10.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1055
}

predicate func_11(Parameter vstack_1055, Variable vi_1058, ArrayExpr target_11) {
		target_11.getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_11.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstack_1055
		and target_11.getArrayOffset().(VariableAccess).getTarget()=vi_1058
}

predicate func_12(BlockStmt target_12) {
		target_12.getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="is_macro"
		and target_12.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="macro"
}

predicate func_14(Variable vi_1058, PostfixDecrExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vi_1058
}

from Function func, Parameter vstack_1055, Variable vi_1058, PointerFieldAccess target_5, AssignExpr target_7, RelationalOperation target_8, VariableAccess target_9, AssignExpr target_10, ArrayExpr target_11, BlockStmt target_12, PostfixDecrExpr target_14
where
not func_2(vstack_1055, vi_1058, target_10, target_11)
and not func_3(vi_1058, target_12, target_8)
and func_5(vstack_1055, target_5)
and func_7(vstack_1055, vi_1058, target_7)
and func_8(vi_1058, target_12, target_8)
and func_9(vstack_1055, vi_1058, target_14, target_9)
and func_10(vstack_1055, target_10)
and func_11(vstack_1055, vi_1058, target_11)
and func_12(target_12)
and func_14(vi_1058, target_14)
and vstack_1055.getType().hasName("const attr_stack *")
and vi_1058.getType().hasName("int")
and vstack_1055.getParentScope+() = func
and vi_1058.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
