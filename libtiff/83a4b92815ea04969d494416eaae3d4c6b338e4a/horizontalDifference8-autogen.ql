/**
 * @name libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-horizontalDifference8
 * @id cpp/libtiff/83a4b92815ea04969d494416eaae3d4c6b338e4a/horizontalDifference8
 * @description libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-libtiff/tif_pixarlog.c-horizontalDifference8 CVE-2016-9533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwp_1057, ExprStmt target_21) {
	exists(PostfixIncrExpr target_0 |
		target_0.getOperand().(VariableAccess).getTarget()=vwp_1057
		and target_0.getOperand().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vip_1056, ExprStmt target_25, ExprStmt target_21) {
	exists(PostfixIncrExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vip_1056
		and target_25.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vstride_1056, Parameter vwp_1057, Parameter vFrom8_1057, Variable vmask_1059, Parameter vip_1056, EqualityOperation target_26, ExprStmt target_28, ExprStmt target_25, ExprStmt target_29, ExprStmt target_30) {
	exists(BitwiseAndExpr target_2 |
		target_2.getLeftOperand().(SubExpr).getLeftOperand() instanceof ArrayExpr
		and target_2.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFrom8_1057
		and target_2.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1056
		and target_2.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vstride_1056
		and target_2.getRightOperand().(VariableAccess).getTarget()=vmask_1059
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_2.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_26.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_28.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_2.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_29.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(VariableAccess).getLocation())
		and target_30.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vstride_1056, Parameter vFrom8_1057, Parameter vip_1056, EqualityOperation target_26, ExprStmt target_28, ExprStmt target_25, ExprStmt target_30) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(VariableAccess).getTarget()=vFrom8_1057
		and target_3.getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1056
		and target_3.getArrayOffset().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vstride_1056
		and target_26.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getArrayOffset().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_28.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(VariableAccess).getLocation())
		and target_3.getArrayBase().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_30.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vwp_1057, ExprStmt target_21) {
	exists(PostfixIncrExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vwp_1057
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vip_1056, ExprStmt target_21) {
	exists(PostfixIncrExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vip_1056)
}

predicate func_6(Parameter vwp_1057, Parameter vFrom8_1057, Parameter vip_1056, ArrayExpr target_6) {
		target_6.getArrayBase().(VariableAccess).getTarget()=vFrom8_1057
		and target_6.getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1056
		and target_6.getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_7(Parameter vwp_1057, VariableAccess target_7) {
		target_7.getTarget()=vwp_1057
}

predicate func_8(Parameter vip_1056, VariableAccess target_8) {
		target_8.getTarget()=vip_1056
}

predicate func_9(Parameter vwp_1057, VariableAccess target_9) {
		target_9.getTarget()=vwp_1057
}

predicate func_10(Parameter vip_1056, VariableAccess target_10) {
		target_10.getTarget()=vip_1056
}

predicate func_11(Parameter vstride_1056, VariableAccess target_11) {
		target_11.getTarget()=vstride_1056
}

predicate func_12(Variable vmask_1059, VariableAccess target_12) {
		target_12.getTarget()=vmask_1059
}

predicate func_13(Parameter vn_1056, Parameter vstride_1056, Parameter vwp_1057, EqualityOperation target_26, ExprStmt target_13) {
		target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vwp_1057
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_1056
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstride_1056
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
}

/*predicate func_14(Parameter vn_1056, Parameter vstride_1056, ExprStmt target_34, EqualityOperation target_26, AddExpr target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vn_1056
		and target_14.getAnOperand().(VariableAccess).getTarget()=vstride_1056
		and target_34.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation())
		and target_26.getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_16(Parameter vn_1056, Parameter vstride_1056, Parameter vip_1056, AssignPointerAddExpr target_16) {
		target_16.getLValue().(VariableAccess).getTarget()=vip_1056
		and target_16.getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_1056
		and target_16.getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstride_1056
		and target_16.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_17(Parameter vstride_1056, Parameter vwp_1057, AssignSubExpr target_17) {
		target_17.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_17.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_1056
		and target_17.getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_17.getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_18(Parameter vstride_1056, Parameter vwp_1057, Variable vmask_1059, AssignAndExpr target_18) {
		target_18.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_18.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_1056
		and target_18.getRValue().(VariableAccess).getTarget()=vmask_1059
}

predicate func_19(Parameter vwp_1057, ExprStmt target_21, PostfixDecrExpr target_19) {
		target_19.getOperand().(VariableAccess).getTarget()=vwp_1057
		and target_19.getOperand().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_20(Parameter vip_1056, ExprStmt target_25, ExprStmt target_21, PostfixDecrExpr target_20) {
		target_20.getOperand().(VariableAccess).getTarget()=vip_1056
		and target_25.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_20.getOperand().(VariableAccess).getLocation())
}

predicate func_21(Parameter vwp_1057, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_21.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
}

predicate func_22(Parameter vwp_1057, ExprStmt target_22) {
		target_22.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vwp_1057
}

predicate func_23(Parameter vip_1056, ExprStmt target_23) {
		target_23.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vip_1056
}

predicate func_25(Parameter vwp_1057, Parameter vFrom8_1057, Parameter vip_1056, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_25.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFrom8_1057
		and target_25.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1056
		and target_25.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_26(Parameter vstride_1056, EqualityOperation target_26) {
		target_26.getAnOperand().(VariableAccess).getTarget()=vstride_1056
		and target_26.getAnOperand().(Literal).getValue()="4"
}

predicate func_28(Parameter vFrom8_1057, Parameter vip_1056, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_28.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFrom8_1057
		and target_28.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1056
		and target_28.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="7"
}

predicate func_29(Parameter vwp_1057, Variable vmask_1059, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1057
		and target_29.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="7"
		and target_29.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_29.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_29.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vmask_1059
}

predicate func_30(Parameter vip_1056, ExprStmt target_30) {
		target_30.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vip_1056
		and target_30.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="4"
}

predicate func_34(Parameter vn_1056, ExprStmt target_34) {
		target_34.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vn_1056
		and target_34.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="4"
}

from Function func, Parameter vn_1056, Parameter vstride_1056, Parameter vwp_1057, Parameter vFrom8_1057, Variable vmask_1059, Parameter vip_1056, ArrayExpr target_6, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, ExprStmt target_13, AssignPointerAddExpr target_16, AssignSubExpr target_17, AssignAndExpr target_18, PostfixDecrExpr target_19, PostfixDecrExpr target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, ExprStmt target_25, EqualityOperation target_26, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_34
where
not func_0(vwp_1057, target_21)
and not func_1(vip_1056, target_25, target_21)
and not func_2(vstride_1056, vwp_1057, vFrom8_1057, vmask_1059, vip_1056, target_26, target_28, target_25, target_29, target_30)
and not func_4(vwp_1057, target_21)
and not func_5(vip_1056, target_21)
and func_6(vwp_1057, vFrom8_1057, vip_1056, target_6)
and func_7(vwp_1057, target_7)
and func_8(vip_1056, target_8)
and func_9(vwp_1057, target_9)
and func_10(vip_1056, target_10)
and func_11(vstride_1056, target_11)
and func_12(vmask_1059, target_12)
and func_13(vn_1056, vstride_1056, vwp_1057, target_26, target_13)
and func_16(vn_1056, vstride_1056, vip_1056, target_16)
and func_17(vstride_1056, vwp_1057, target_17)
and func_18(vstride_1056, vwp_1057, vmask_1059, target_18)
and func_19(vwp_1057, target_21, target_19)
and func_20(vip_1056, target_25, target_21, target_20)
and func_21(vwp_1057, target_21)
and func_22(vwp_1057, target_22)
and func_23(vip_1056, target_23)
and func_25(vwp_1057, vFrom8_1057, vip_1056, target_25)
and func_26(vstride_1056, target_26)
and func_28(vFrom8_1057, vip_1056, target_28)
and func_29(vwp_1057, vmask_1059, target_29)
and func_30(vip_1056, target_30)
and func_34(vn_1056, target_34)
and vn_1056.getType().hasName("int")
and vstride_1056.getType().hasName("int")
and vwp_1057.getType().hasName("unsigned short *")
and vFrom8_1057.getType().hasName("uint16 *")
and vmask_1059.getType().hasName("int")
and vip_1056.getType().hasName("unsigned char *")
and vn_1056.getFunction() = func
and vstride_1056.getFunction() = func
and vwp_1057.getFunction() = func
and vFrom8_1057.getFunction() = func
and vmask_1059.(LocalVariable).getFunction() = func
and vip_1056.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
