/**
 * @name imagemagick-76401e172ea3a55182be2b8e2aca4d07270f6da6-EqualizeImage
 * @id cpp/imagemagick/76401e172ea3a55182be2b8e2aca4d07270f6da6/EqualizeImage
 * @description imagemagick-76401e172ea3a55182be2b8e2aca4d07270f6da6-MagickCore/enhance.c-EqualizeImage CVE-2016-6520
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_1499, Parameter vimage_1498, ExprStmt target_1, ExprStmt target_2, MulExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("SyncImagePixelCache")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1498
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vexception_1499
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vexception_1499, Parameter vimage_1498, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_1499
		and target_1.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_1.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_1.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_1.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1498
}

predicate func_2(Parameter vimage_1498, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("LogMagickEvent")
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="%s"
		and target_2.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="filename"
		and target_2.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1498
}

predicate func_3(Parameter vimage_1498, MulExpr target_3) {
		target_3.getLeftOperand().(FunctionCall).getTarget().hasName("GetPixelChannels")
		and target_3.getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1498
		and target_3.getRightOperand().(SizeofExprOperator).getValue()="8"
}

from Function func, Parameter vexception_1499, Parameter vimage_1498, ExprStmt target_1, ExprStmt target_2, MulExpr target_3
where
not func_0(vexception_1499, vimage_1498, target_1, target_2, target_3, func)
and func_1(vexception_1499, vimage_1498, target_1)
and func_2(vimage_1498, target_2)
and func_3(vimage_1498, target_3)
and vexception_1499.getType().hasName("ExceptionInfo *")
and vimage_1498.getType().hasName("Image *")
and vexception_1499.getParentScope+() = func
and vimage_1498.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
