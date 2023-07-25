/**
 * @name sqlite3-57f7ece78410a8aae86aa4625fb7556897db384c-sqlite3ExprCodeTarget
 * @id cpp/sqlite3/57f7ece78410a8aae86aa4625fb7556897db384c/sqlite3ExprCodeTarget
 * @description sqlite3-57f7ece78410a8aae86aa4625fb7556897db384c-src/expr.c-sqlite3ExprCodeTarget CVE-2019-19242
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpExpr_3562, Variable vaff_3608, EqualityOperation target_3, FunctionCall target_1, ValueFieldAccess target_4, RelationalOperation target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3562
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vaff_3608
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vaff_3608
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="affExpr"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3562
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpExpr_3562, FunctionCall target_1) {
		target_1.getTarget().hasName("sqlite3TableColumnAffinity")
		and target_1.getArgument(0).(ValueFieldAccess).getTarget().getName()="pTab"
		and target_1.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_1.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3562
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="iColumn"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3562
}

predicate func_2(Function func, Initializer target_2) {
		target_2.getExpr() instanceof FunctionCall
		and target_2.getExpr().getEnclosingFunction() = func
}

predicate func_3(Parameter vpExpr_3562, EqualityOperation target_3) {
		target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3562
		and target_3.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vpExpr_3562, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="pTab"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3562
}

predicate func_5(Variable vaff_3608, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vaff_3608
		and target_5.getLesserOperand().(Literal).getValue()="65"
}

from Function func, Parameter vpExpr_3562, Variable vaff_3608, FunctionCall target_1, Initializer target_2, EqualityOperation target_3, ValueFieldAccess target_4, RelationalOperation target_5
where
not func_0(vpExpr_3562, vaff_3608, target_3, target_1, target_4, target_5)
and func_1(vpExpr_3562, target_1)
and func_2(func, target_2)
and func_3(vpExpr_3562, target_3)
and func_4(vpExpr_3562, target_4)
and func_5(vaff_3608, target_5)
and vpExpr_3562.getType().hasName("Expr *")
and vaff_3608.getType().hasName("int")
and vpExpr_3562.getFunction() = func
and vaff_3608.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
