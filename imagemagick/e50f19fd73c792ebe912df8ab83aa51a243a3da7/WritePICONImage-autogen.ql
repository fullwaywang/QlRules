/**
 * @name imagemagick-e50f19fd73c792ebe912df8ab83aa51a243a3da7-WritePICONImage
 * @id cpp/imagemagick/e50f19fd73c792ebe912df8ab83aa51a243a3da7/WritePICONImage
 * @description imagemagick-e50f19fd73c792ebe912df8ab83aa51a243a3da7-coders/xpm.c-WritePICONImage CVE-2022-0284
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_623, LogicalAndExpr target_2, ExprStmt target_3, VariableAccess target_0) {
		target_0.getTarget()=vimage_623
		and target_0.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("GetPixelAlpha")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter vimage_623, ExprStmt target_4, ExprStmt target_5, VariableAccess target_1) {
		target_1.getTarget()=vimage_623
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("GetPixelAlpha")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getLocation())
		and target_1.getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_2(Parameter vimage_623, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IdentifyImageCoderGray")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_623
}

predicate func_3(Parameter vimage_623, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_3.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_3.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="MemoryAllocationError"
		and target_3.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_623
}

predicate func_4(Parameter vimage_623, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_623
}

predicate func_5(Parameter vimage_623, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("WriteBlobString")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_623
		and target_5.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="/* XPM */\n"
}

from Function func, Parameter vimage_623, VariableAccess target_0, VariableAccess target_1, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
func_0(vimage_623, target_2, target_3, target_0)
and func_1(vimage_623, target_4, target_5, target_1)
and func_2(vimage_623, target_2)
and func_3(vimage_623, target_3)
and func_4(vimage_623, target_4)
and func_5(vimage_623, target_5)
and vimage_623.getType().hasName("Image *")
and vimage_623.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
