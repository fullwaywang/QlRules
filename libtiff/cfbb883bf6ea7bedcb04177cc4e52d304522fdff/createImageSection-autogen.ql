/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-createImageSection
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/createImageSection
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-createImageSection CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsectsize_7547, ExprStmt target_10) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vsectsize_7547
		and target_0.getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsectsize_7547
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsectsize_7547, ExprStmt target_11, RelationalOperation target_12) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vsectsize_7547
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsectsize_7547
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsectsize_7547, RelationalOperation target_12, ExprStmt target_13) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vsectsize_7547
		and target_2.getAnOperand().(Literal).getValue()="3"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsectsize_7547
		and target_12.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsectsize_7547, ExprStmt target_14, ExprStmt target_15) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vsectsize_7547
		and target_3.getAnOperand().(Literal).getValue()="3"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsectsize_7547
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vsectsize_7547, ExprStmt target_13, ExprStmt target_16) {
	exists(AddExpr target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=vsectsize_7547
		and target_4.getAnOperand().(Literal).getValue()="3"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsectsize_7547
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vsectsize_7547, VariableAccess target_5) {
		target_5.getTarget()=vsectsize_7547
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_6(Parameter vsectsize_7547, VariableAccess target_6) {
		target_6.getTarget()=vsectsize_7547
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_7(Parameter vsectsize_7547, VariableAccess target_7) {
		target_7.getTarget()=vsectsize_7547
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
}

predicate func_8(Parameter vsectsize_7547, VariableAccess target_8) {
		target_8.getTarget()=vsectsize_7547
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_9(Parameter vsectsize_7547, VariableAccess target_9) {
		target_9.getTarget()=vsectsize_7547
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_10(Parameter vsectsize_7547, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsectsize_7547
}

predicate func_11(Parameter vsectsize_7547, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsectsize_7547
}

predicate func_12(Parameter vsectsize_7547, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getLesserOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vsectsize_7547
}

predicate func_13(Parameter vsectsize_7547, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsectsize_7547
}

predicate func_14(Parameter vsectsize_7547, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFrealloc")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsectsize_7547
}

predicate func_15(Parameter vsectsize_7547, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_15.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_15.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsectsize_7547
}

predicate func_16(Parameter vsectsize_7547, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsectsize_7547
}

from Function func, Parameter vsectsize_7547, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, ExprStmt target_10, ExprStmt target_11, RelationalOperation target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16
where
not func_0(vsectsize_7547, target_10)
and not func_1(vsectsize_7547, target_11, target_12)
and not func_2(vsectsize_7547, target_12, target_13)
and not func_3(vsectsize_7547, target_14, target_15)
and not func_4(vsectsize_7547, target_13, target_16)
and func_5(vsectsize_7547, target_5)
and func_6(vsectsize_7547, target_6)
and func_7(vsectsize_7547, target_7)
and func_8(vsectsize_7547, target_8)
and func_9(vsectsize_7547, target_9)
and func_10(vsectsize_7547, target_10)
and func_11(vsectsize_7547, target_11)
and func_12(vsectsize_7547, target_12)
and func_13(vsectsize_7547, target_13)
and func_14(vsectsize_7547, target_14)
and func_15(vsectsize_7547, target_15)
and func_16(vsectsize_7547, target_16)
and vsectsize_7547.getType().hasName("uint32_t")
and vsectsize_7547.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
