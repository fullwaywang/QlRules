/**
 * @name imagemagick-a9d563d3d73874312080d30dc4ba07cecad56192-WriteOnePNGImage
 * @id cpp/imagemagick/a9d563d3d73874312080d30dc4ba07cecad56192/WriteOnePNGImage
 * @description imagemagick-a9d563d3d73874312080d30dc4ba07cecad56192-coders/png.c-WriteOnePNGImage CVE-2020-27752
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimage_8396, ExprStmt target_7) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(FunctionCall).getTarget().hasName("GetPixelChannels")
		and target_0.getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_8396
		and target_0.getRightOperand() instanceof SizeofExprOperator
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireVirtualMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof AddExpr
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
		and target_7.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vrowbytes_8515, Variable vimage_8396, ExprStmt target_8, ExprStmt target_10) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vrowbytes_8515
		and target_1.getRightOperand().(FunctionCall).getTarget().hasName("GetPixelChannels")
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_8396
		and target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Function func, SizeofExprOperator target_2) {
		target_2.getValue()="1"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vrowbytes_8515, VariableAccess target_3) {
		target_3.getTarget()=vrowbytes_8515
}

predicate func_4(Variable vrowbytes_8515, VariableAccess target_4) {
		target_4.getTarget()=vrowbytes_8515
}

predicate func_5(Variable vrowbytes_8515, ExprStmt target_8, AddExpr target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vrowbytes_8515
		and target_5.getAnOperand().(Literal).getValue()="256"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireVirtualMemory")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
		and target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
}

predicate func_6(Variable vrowbytes_8515, AddExpr target_5, AddExpr target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vrowbytes_8515
		and target_6.getAnOperand().(Literal).getValue()="256"
		and target_5.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
}

predicate func_7(Variable vrowbytes_8515, Variable vimage_8396, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrowbytes_8515
		and target_7.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="columns"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_8396
}

predicate func_8(Variable vrowbytes_8515, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("LogMagickEvent")
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="    Allocating %.20g bytes of memory for pixels"
		and target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vrowbytes_8515
}

predicate func_10(Variable vimage_8396, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumInfo")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vimage_8396
}

from Function func, Variable vrowbytes_8515, Variable vimage_8396, SizeofExprOperator target_2, VariableAccess target_3, VariableAccess target_4, AddExpr target_5, AddExpr target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_10
where
not func_0(vimage_8396, target_7)
and not func_1(vrowbytes_8515, vimage_8396, target_8, target_10)
and func_2(func, target_2)
and func_3(vrowbytes_8515, target_3)
and func_4(vrowbytes_8515, target_4)
and func_5(vrowbytes_8515, target_8, target_5)
and func_6(vrowbytes_8515, target_5, target_6)
and func_7(vrowbytes_8515, vimage_8396, target_7)
and func_8(vrowbytes_8515, target_8)
and func_10(vimage_8396, target_10)
and vrowbytes_8515.getType().hasName("size_t")
and vimage_8396.getType().hasName("Image *")
and vrowbytes_8515.getParentScope+() = func
and vimage_8396.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
