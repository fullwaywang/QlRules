/**
 * @name imagemagick-1cc6f0ccc92c20c7cab6c4a7335daf29c91f0d8e-EqualizeImage
 * @id cpp/imagemagick/1cc6f0ccc92c20c7cab6c4a7335daf29c91f0d8e/EqualizeImage
 * @description imagemagick-1cc6f0ccc92c20c7cab6c4a7335daf29c91f0d8e-MagickCore/enhance.c-EqualizeImage CVE-2017-12876
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_1502, Parameter vimage_1501, ExprStmt target_1, EqualityOperation target_2, EqualityOperation target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("SyncImagePixelCache")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1501
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vexception_1502
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vexception_1502, Parameter vimage_1501, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_1502
		and target_1.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_1.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_1.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_1.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_1.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1501
}

predicate func_2(Parameter vimage_1501, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="signature"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1501
		and target_2.getAnOperand() instanceof Literal
}

predicate func_3(Parameter vimage_1501, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="debug"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1501
}

from Function func, Parameter vexception_1502, Parameter vimage_1501, ExprStmt target_1, EqualityOperation target_2, EqualityOperation target_3
where
not func_0(vexception_1502, vimage_1501, target_1, target_2, target_3, func)
and func_1(vexception_1502, vimage_1501, target_1)
and func_2(vimage_1501, target_2)
and func_3(vimage_1501, target_3)
and vexception_1502.getType().hasName("ExceptionInfo *")
and vimage_1501.getType().hasName("Image *")
and vexception_1502.getParentScope+() = func
and vimage_1501.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
