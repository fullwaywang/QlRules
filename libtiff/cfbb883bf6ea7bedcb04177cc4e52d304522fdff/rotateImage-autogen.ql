/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-rotateImage
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/rotateImage
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-rotateImage CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuffsize_8608, ExprStmt target_6, ExprStmt target_7) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vbuffsize_8608
		and target_0.getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffsize_8608
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuffsize_8608, NotExpr target_8, ExprStmt target_9) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vbuffsize_8608
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="rotateImage"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate rotation buffer of %1u bytes"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffsize_8608
		and target_8.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Variable vbuffsize_8608, ExprStmt target_7) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vbuffsize_8608
		and target_2.getAnOperand().(Literal).getValue()="3"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffsize_8608
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vbuffsize_8608, VariableAccess target_3) {
		target_3.getTarget()=vbuffsize_8608
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_4(Variable vbuffsize_8608, VariableAccess target_4) {
		target_4.getTarget()=vbuffsize_8608
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="rotateImage"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate rotation buffer of %1u bytes"
}

predicate func_5(Variable vbuffsize_8608, VariableAccess target_5) {
		target_5.getTarget()=vbuffsize_8608
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
}

predicate func_6(Variable vbuffsize_8608, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffsize_8608
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_7(Variable vbuffsize_8608, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_7.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="rotateImage"
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate rotation buffer of %1u bytes"
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffsize_8608
}

predicate func_8(Variable vbuffsize_8608, NotExpr target_8) {
		target_8.getOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_8.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_8.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffsize_8608
}

predicate func_9(Variable vbuffsize_8608, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_9.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffsize_8608
}

from Function func, Variable vbuffsize_8608, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, ExprStmt target_6, ExprStmt target_7, NotExpr target_8, ExprStmt target_9
where
not func_0(vbuffsize_8608, target_6, target_7)
and not func_1(vbuffsize_8608, target_8, target_9)
and not func_2(vbuffsize_8608, target_7)
and func_3(vbuffsize_8608, target_3)
and func_4(vbuffsize_8608, target_4)
and func_5(vbuffsize_8608, target_5)
and func_6(vbuffsize_8608, target_6)
and func_7(vbuffsize_8608, target_7)
and func_8(vbuffsize_8608, target_8)
and func_9(vbuffsize_8608, target_9)
and vbuffsize_8608.getType().hasName("uint32_t")
and vbuffsize_8608.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
