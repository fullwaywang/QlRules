/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-mirrorImage
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/mirrorImage
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-mirrorImage CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrowsize_9265, ExprStmt target_10, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="3"
		and target_0.getParent().(AddExpr).getParent().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_10.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(AddExpr).getParent().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vrowsize_9265, ExprStmt target_11, ExprStmt target_12) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrowsize_9265
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Variable vrowsize_9265, ExprStmt target_13, ExprStmt target_14) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_2.getAnOperand().(Literal).getValue()="3"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="mirrorImage"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate mirror line buffer of %1u bytes"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrowsize_9265
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vrowsize_9265, Variable vline_buff_9266, VariableAccess target_15, ExprStmt target_16, FunctionCall target_17) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_buff_9266
		and target_3.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_3.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_15
		and target_3.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getArgument(4).(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vrowsize_9265, Variable vline_buff_9266, ExprStmt target_16) {
	exists(AddExpr target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_4.getAnOperand().(Literal).getValue()="3"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_buff_9266
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrowsize_9265
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

*/
predicate func_5(Variable vrowsize_9265, Variable vline_buff_9266, EqualityOperation target_18, AddExpr target_19, ExprStmt target_20, NotExpr target_21) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_buff_9266
		and target_5.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_19.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_21.getOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Variable vrowsize_9265, Variable vline_buff_9266, ExprStmt target_20, ExprStmt target_22) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("_TIFFmemset")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vline_buff_9266
		and target_6.getArgument(1).(CharLiteral).getValue()="0"
		and target_6.getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_6.getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_20.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_6.getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_7(Variable vrowsize_9265, VariableAccess target_7) {
		target_7.getTarget()=vrowsize_9265
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_8(Variable vrowsize_9265, VariableAccess target_8) {
		target_8.getTarget()=vrowsize_9265
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="mirrorImage"
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate mirror line buffer of %1u bytes"
}

predicate func_9(Variable vrowsize_9265, Variable vline_buff_9266, VariableAccess target_9) {
		target_9.getTarget()=vrowsize_9265
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_buff_9266
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
}

predicate func_10(Variable vrowsize_9265, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_10.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_10.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_10.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
}

predicate func_11(Variable vrowsize_9265, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrowsize_9265
		and target_11.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_11.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_11.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_11.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_11.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_12(Variable vrowsize_9265, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_12.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="mirrorImage"
		and target_12.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to allocate mirror line buffer of %1u bytes"
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrowsize_9265
}

predicate func_13(Variable vrowsize_9265, Variable vline_buff_9266, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vline_buff_9266
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrowsize_9265
}

predicate func_14(Variable vrowsize_9265, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_15(Parameter vmirror_9261, VariableAccess target_15) {
		target_15.getTarget()=vmirror_9261
}

predicate func_16(Variable vrowsize_9265, Variable vline_buff_9266, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vline_buff_9266
		and target_16.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrowsize_9265
}

predicate func_17(Variable vline_buff_9266, FunctionCall target_17) {
		target_17.getTarget().hasName("reverseSamples16bits")
		and target_17.getArgument(0).(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_17.getArgument(1).(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_17.getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_17.getArgument(3).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_17.getArgument(4).(VariableAccess).getTarget()=vline_buff_9266
}

predicate func_18(EqualityOperation target_18) {
		target_18.getAnOperand().(RemExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_18.getAnOperand().(RemExpr).getRightOperand().(Literal).getValue()="8"
		and target_18.getAnOperand().(Literal).getValue()="0"
}

predicate func_19(Variable vrowsize_9265, AddExpr target_19) {
		target_19.getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_19.getAnOperand() instanceof Literal
}

predicate func_20(Variable vrowsize_9265, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_20.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_20.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrowsize_9265
}

predicate func_21(Variable vrowsize_9265, Variable vline_buff_9266, NotExpr target_21) {
		target_21.getOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vline_buff_9266
		and target_21.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_21.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrowsize_9265
		and target_21.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand() instanceof Literal
}

predicate func_22(Variable vrowsize_9265, Variable vline_buff_9266, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemset")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_buff_9266
		and target_22.getExpr().(FunctionCall).getArgument(1).(CharLiteral).getValue()="0"
		and target_22.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrowsize_9265
}

from Function func, Parameter vmirror_9261, Variable vrowsize_9265, Variable vline_buff_9266, Literal target_0, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, VariableAccess target_15, ExprStmt target_16, FunctionCall target_17, EqualityOperation target_18, AddExpr target_19, ExprStmt target_20, NotExpr target_21, ExprStmt target_22
where
func_0(vrowsize_9265, target_10, target_0)
and not func_1(vrowsize_9265, target_11, target_12)
and not func_2(vrowsize_9265, target_13, target_14)
and not func_3(vrowsize_9265, vline_buff_9266, target_15, target_16, target_17)
and not func_5(vrowsize_9265, vline_buff_9266, target_18, target_19, target_20, target_21)
and not func_6(vrowsize_9265, vline_buff_9266, target_20, target_22)
and func_7(vrowsize_9265, target_7)
and func_8(vrowsize_9265, target_8)
and func_9(vrowsize_9265, vline_buff_9266, target_9)
and func_10(vrowsize_9265, target_10)
and func_11(vrowsize_9265, target_11)
and func_12(vrowsize_9265, target_12)
and func_13(vrowsize_9265, vline_buff_9266, target_13)
and func_14(vrowsize_9265, target_14)
and func_15(vmirror_9261, target_15)
and func_16(vrowsize_9265, vline_buff_9266, target_16)
and func_17(vline_buff_9266, target_17)
and func_18(target_18)
and func_19(vrowsize_9265, target_19)
and func_20(vrowsize_9265, target_20)
and func_21(vrowsize_9265, vline_buff_9266, target_21)
and func_22(vrowsize_9265, vline_buff_9266, target_22)
and vmirror_9261.getType().hasName("uint16_t")
and vrowsize_9265.getType().hasName("uint32_t")
and vline_buff_9266.getType().hasName("unsigned char *")
and vmirror_9261.getFunction() = func
and vrowsize_9265.(LocalVariable).getFunction() = func
and vline_buff_9266.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
