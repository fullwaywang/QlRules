/**
 * @name imagemagick-5d71e23b853461dd3628cd1218834fcf13938365-SVGStripString
 * @id cpp/imagemagick/5d71e23b853461dd3628cd1218834fcf13938365/SVGStripString
 * @description imagemagick-5d71e23b853461dd3628cd1218834fcf13938365-coders/svg.c-SVGStripString CVE-2018-18023
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_559, LogicalAndExpr target_2, ExprStmt target_0) {
		target_0.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_559
		and target_0.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_1(LogicalAndExpr target_3, Function func, BreakStmt target_1) {
		target_1.toString() = "break;"
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vp_559, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_559
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_559
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
}

predicate func_3(Variable vp_559, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_559
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_559
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
}

from Function func, Variable vp_559, ExprStmt target_0, BreakStmt target_1, LogicalAndExpr target_2, LogicalAndExpr target_3
where
func_0(vp_559, target_2, target_0)
and func_1(target_3, func, target_1)
and func_2(vp_559, target_2)
and func_3(vp_559, target_3)
and vp_559.getType().hasName("char *")
and vp_559.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
