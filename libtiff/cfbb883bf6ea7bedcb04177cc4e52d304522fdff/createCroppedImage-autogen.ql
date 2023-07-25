/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-createCroppedImage
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/createCroppedImage
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-createCroppedImage CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcropsize_7838, ExprStmt target_10, ExprStmt target_11) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vcropsize_7838
		and target_0.getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcropsize_7838
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcropsize_7838, ExprStmt target_12, ExprStmt target_13) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vcropsize_7838
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcropsize_7838
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcropsize_7838, RelationalOperation target_14, ExprStmt target_15) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vcropsize_7838
		and target_2.getAnOperand().(Literal).getValue()="3"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcropsize_7838
		and target_14.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vcropsize_7838, ExprStmt target_16, ExprStmt target_17) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vcropsize_7838
		and target_3.getAnOperand().(Literal).getValue()="3"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcropsize_7838
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_17.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_4(Variable vcropsize_7838, ExprStmt target_15) {
	exists(AddExpr target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=vcropsize_7838
		and target_4.getAnOperand().(Literal).getValue()="3"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcropsize_7838
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vcropsize_7838, VariableAccess target_5) {
		target_5.getTarget()=vcropsize_7838
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_6(Variable vcropsize_7838, VariableAccess target_6) {
		target_6.getTarget()=vcropsize_7838
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_7(Variable vcropsize_7838, VariableAccess target_7) {
		target_7.getTarget()=vcropsize_7838
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
}

predicate func_8(Variable vcropsize_7838, VariableAccess target_8) {
		target_8.getTarget()=vcropsize_7838
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_9(Variable vcropsize_7838, VariableAccess target_9) {
		target_9.getTarget()=vcropsize_7838
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_10(Variable vcropsize_7838, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcropsize_7838
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bufftotal"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("crop_mask *")
}

predicate func_11(Variable vcropsize_7838, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_11.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcropsize_7838
}

predicate func_12(Variable vcropsize_7838, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcropsize_7838
}

predicate func_13(Variable vcropsize_7838, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcropsize_7838
}

predicate func_14(Variable vcropsize_7838, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getLesserOperand().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_14.getGreaterOperand().(VariableAccess).getTarget()=vcropsize_7838
}

predicate func_15(Variable vcropsize_7838, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcropsize_7838
}

predicate func_16(Variable vcropsize_7838, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcropsize_7838
}

predicate func_17(Variable vcropsize_7838, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_17.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_17.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcropsize_7838
}

from Function func, Variable vcropsize_7838, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, RelationalOperation target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17
where
not func_0(vcropsize_7838, target_10, target_11)
and not func_1(vcropsize_7838, target_12, target_13)
and not func_2(vcropsize_7838, target_14, target_15)
and not func_3(vcropsize_7838, target_16, target_17)
and not func_4(vcropsize_7838, target_15)
and func_5(vcropsize_7838, target_5)
and func_6(vcropsize_7838, target_6)
and func_7(vcropsize_7838, target_7)
and func_8(vcropsize_7838, target_8)
and func_9(vcropsize_7838, target_9)
and func_10(vcropsize_7838, target_10)
and func_11(vcropsize_7838, target_11)
and func_12(vcropsize_7838, target_12)
and func_13(vcropsize_7838, target_13)
and func_14(vcropsize_7838, target_14)
and func_15(vcropsize_7838, target_15)
and func_16(vcropsize_7838, target_16)
and func_17(vcropsize_7838, target_17)
and vcropsize_7838.getType().hasName("tsize_t")
and vcropsize_7838.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
