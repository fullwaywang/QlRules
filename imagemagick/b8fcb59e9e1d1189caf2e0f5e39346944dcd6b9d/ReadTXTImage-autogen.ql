/**
 * @name imagemagick-b8fcb59e9e1d1189caf2e0f5e39346944dcd6b9d-ReadTXTImage
 * @id cpp/imagemagick/b8fcb59e9e1d1189caf2e0f5e39346944dcd6b9d/ReadTXTImage
 * @description imagemagick-b8fcb59e9e1d1189caf2e0f5e39346944dcd6b9d-coders/txt.c-ReadTXTImage CVE-2017-18273
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtext_380, EqualityOperation target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtext_380
		and target_0.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vtext_380, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("strchr")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtext_380
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="37"
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vtext_380, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ReadBlobString")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtext_380
}

from Function func, Variable vtext_380, EqualityOperation target_1, ExprStmt target_2
where
not func_0(vtext_380, target_1, target_2)
and func_1(vtext_380, target_1)
and func_2(vtext_380, target_2)
and vtext_380.getType().hasName("char[4096]")
and vtext_380.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
