/**
 * @name imagemagick-d4ec73f866a7c42a2e7f301fcd696e5cb7a7d3ab-WritePSDChannels
 * @id cpp/imagemagick/d4ec73f866a7c42a2e7f301fcd696e5cb7a7d3ab/WritePSDChannels
 * @description imagemagick-d4ec73f866a7c42a2e7f301fcd696e5cb7a7d3ab-coders/psd.c-WritePSDChannels CVE-2017-5509
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_2612, ExprStmt target_1, VariableAccess target_0) {
		target_0.getTarget()=vimage_2612
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireCompactPixels")
		and target_0.getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Parameter vimage_2612, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("TellBlob")
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_2612
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

from Function func, Parameter vimage_2612, VariableAccess target_0, ExprStmt target_1
where
func_0(vimage_2612, target_1, target_0)
and func_1(vimage_2612, target_1)
and vimage_2612.getType().hasName("Image *")
and vimage_2612.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
