/**
 * @name sqlite3-75e95e1fcd52d3ec8282edb75ac8cd0814095d54-exprListAppendList
 * @id cpp/sqlite3/75e95e1fcd52d3ec8282edb75ac8cd0814095d54/exprListAppendList
 * @description sqlite3-75e95e1fcd52d3ec8282edb75ac8cd0814095d54-src/window.c-exprListAppendList CVE-2019-19880
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vpDup_897, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="zToken"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpDup_897
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Variable vpDup_897, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpDup_897
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpDup_897
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="152"
}

predicate func_3(Variable vpDup_897, ExprStmt target_3) {
		target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpDup_897
		and target_3.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="3489659903"
}

predicate func_4(Variable vpDup_897, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ExprList *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3ExprListAppend")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Parse *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("ExprList *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpDup_897
}

from Function func, Variable vpDup_897, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(func)
and not func_1(vpDup_897, target_2, target_3, target_4)
and func_2(vpDup_897, target_2)
and func_3(vpDup_897, target_3)
and func_4(vpDup_897, target_4)
and vpDup_897.getType().hasName("Expr *")
and vpDup_897.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
