/**
 * @name libxml2-1098c30a040e72a4654968547f415be4e4c40fe7-xmlXIncludeDoProcess
 * @id cpp/libxml2/1098c30a040e72a4654968547f415be4e4c40fe7/xmlXIncludeDoProcess
 * @description libxml2-1098c30a040e72a4654968547f415be4e4c40fe7-xmlXIncludeDoProcess CVE-2021-3518
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vcur_2377) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_2377
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof PointerFieldAccess
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;")
}

predicate func_3(Variable vcur_2377) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="children"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_3.getAnOperand().(Literal).getValue()="0")
}

predicate func_4(Variable vcur_2377) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="children"
		and target_4.getQualifier().(VariableAccess).getTarget()=vcur_2377)
}

from Function func, Variable vcur_2377
where
not func_2(vcur_2377)
and func_3(vcur_2377)
and func_4(vcur_2377)
and vcur_2377.getType().hasName("xmlNodePtr")
and vcur_2377.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
