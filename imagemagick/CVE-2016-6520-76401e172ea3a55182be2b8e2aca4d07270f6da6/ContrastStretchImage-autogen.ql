/**
 * @name imagemagick-76401e172ea3a55182be2b8e2aca4d07270f6da6-ContrastStretchImage
 * @id cpp/imagemagick/76401e172ea3a55182be2b8e2aca4d07270f6da6/ContrastStretchImage
 * @description imagemagick-76401e172ea3a55182be2b8e2aca4d07270f6da6-MagickCore/enhance.c-ContrastStretchImage CVE-2016-6520
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_1017, Parameter vimage_1016, ExprStmt target_1, ExprStmt target_2, FunctionCall target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("SyncImagePixelCache")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1016
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vexception_1017
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vexception_1017, Parameter vimage_1016, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("SetImageColorspace")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1016
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexception_1017
}

predicate func_2(Parameter vexception_1017, Parameter vimage_1016, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_1017
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_2.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1016
}

predicate func_3(Parameter vimage_1016, FunctionCall target_3) {
		target_3.getTarget().hasName("GetPixelChannels")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vimage_1016
}

from Function func, Parameter vexception_1017, Parameter vimage_1016, ExprStmt target_1, ExprStmt target_2, FunctionCall target_3
where
not func_0(vexception_1017, vimage_1016, target_1, target_2, target_3, func)
and func_1(vexception_1017, vimage_1016, target_1)
and func_2(vexception_1017, vimage_1016, target_2)
and func_3(vimage_1016, target_3)
and vexception_1017.getType().hasName("ExceptionInfo *")
and vimage_1016.getType().hasName("Image *")
and vexception_1017.getParentScope+() = func
and vimage_1016.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
