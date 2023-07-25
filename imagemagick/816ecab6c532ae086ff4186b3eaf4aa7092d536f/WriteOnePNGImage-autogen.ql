/**
 * @name imagemagick-816ecab6c532ae086ff4186b3eaf4aa7092d536f-WriteOnePNGImage
 * @id cpp/imagemagick/816ecab6c532ae086ff4186b3eaf4aa7092d536f/WriteOnePNGImage
 * @description imagemagick-816ecab6c532ae086ff4186b3eaf4aa7092d536f-coders/png.c-WriteOnePNGImage CVE-2017-11522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimage_8134, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_8134
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vimage_8134, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_8134
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CloneImage")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_2(Variable vimage_8134, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_2.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_8134
}

from Function func, Variable vimage_8134, ExprStmt target_1, ExprStmt target_2
where
not func_0(vimage_8134, target_1, target_2, func)
and func_1(vimage_8134, target_1)
and func_2(vimage_8134, target_2)
and vimage_8134.getType().hasName("Image *")
and vimage_8134.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
