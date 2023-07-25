/**
 * @name libxml2-1098c30a040e72a4654968547f415be4e4c40fe7-xmlXIncludeDoProcess
 * @id cpp/libxml2/1098c30a040e72a4654968547f415be4e4c40fe7/xmlXIncludeDoProcess
 * @description libxml2-1098c30a040e72a4654968547f415be4e4c40fe7-xinclude.c-xmlXIncludeDoProcess CVE-2021-3518
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vcur_2377, BlockStmt target_10) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_10)
}

predicate func_3(Variable vcur_2377, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="children"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vcur_2377, VariableAccess target_4) {
		target_4.getTarget()=vcur_2377
}

predicate func_5(Variable vcur_2377, VariableAccess target_5) {
		target_5.getTarget()=vcur_2377
}

predicate func_6(Variable vcur_2377, BlockStmt target_10, LogicalAndExpr target_6) {
		target_6.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="children"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="children"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="children"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_10
}

/*predicate func_7(Variable vcur_2377, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="children"
		and target_7.getQualifier().(VariableAccess).getTarget()=vcur_2377
}

*/
/*predicate func_8(Variable vcur_2377, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="children"
		and target_8.getQualifier().(VariableAccess).getTarget()=vcur_2377
}

*/
/*predicate func_9(Variable vcur_2377, BlockStmt target_10, EqualityOperation target_9) {
		target_9.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="children"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="children"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="children"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_9.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_10
}

*/
predicate func_10(Variable vcur_2377, BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_2377
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_2377
}

from Function func, Variable vcur_2377, EqualityOperation target_3, VariableAccess target_4, VariableAccess target_5, LogicalAndExpr target_6, BlockStmt target_10
where
not func_2(vcur_2377, target_10)
and func_3(vcur_2377, target_3)
and func_4(vcur_2377, target_4)
and func_5(vcur_2377, target_5)
and func_6(vcur_2377, target_10, target_6)
and func_10(vcur_2377, target_10)
and vcur_2377.getType().hasName("xmlNodePtr")
and vcur_2377.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
