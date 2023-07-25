/**
 * @name libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-horizontalDifference16
 * @id cpp/libtiff/83a4b92815ea04969d494416eaae3d4c6b338e4a/horizontalDifference16
 * @description libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-libtiff/tif_pixarlog.c-horizontalDifference16 CVE-2016-9533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vn_1002, ExprStmt target_28, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="2"
		and target_0.getParent().(SubExpr).getParent().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_1002
		and target_28.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getParent().(SubExpr).getParent().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
}

predicate func_1(Parameter vstride_1002, Parameter vwp_1003, ExprStmt target_30, ExprStmt target_32, VariableAccess target_1) {
		target_1.getTarget()=vwp_1003
		and vwp_1003.getIndex() = 3
		and target_1.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_1002
		and target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Parameter vwp_1003, ExprStmt target_25) {
	exists(PostfixIncrExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vwp_1003
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vip_1002, ExprStmt target_32, ExprStmt target_25) {
	exists(PostfixIncrExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vip_1002
		and target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vstride_1002, Parameter vwp_1003, Parameter vFrom14_1003, Variable vmask_1005, ExprStmt target_30, ExprStmt target_35, ExprStmt target_32, ExprStmt target_36) {
	exists(BitwiseAndExpr target_4 |
		target_4.getLeftOperand().(SubExpr).getLeftOperand() instanceof ArrayExpr
		and target_4.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFrom14_1003
		and target_4.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("unsigned short *")
		and target_4.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vstride_1002
		and target_4.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_4.getRightOperand().(VariableAccess).getTarget()=vmask_1005
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_4.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_35.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_4.getLeftOperand().(SubExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_36.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_4.getRightOperand().(VariableAccess).getLocation()))
}

/*predicate func_5(Parameter vstride_1002, Parameter vFrom14_1003, ExprStmt target_30, ExprStmt target_35, ExprStmt target_32) {
	exists(ArrayExpr target_5 |
		target_5.getArrayBase().(VariableAccess).getTarget()=vFrom14_1003
		and target_5.getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("unsigned short *")
		and target_5.getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vstride_1002
		and target_5.getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_5.getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_35.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getArrayBase().(VariableAccess).getLocation())
		and target_5.getArrayBase().(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

*/
/*predicate func_6(Parameter vstride_1002, Parameter vwp_1003, ExprStmt target_30) {
	exists(UnaryMinusExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vstride_1002
		and target_6.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_6.getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_7(Parameter vwp_1003, ExprStmt target_25) {
	exists(PostfixIncrExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vwp_1003
		and target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_7.getOperand().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vip_1002, ExprStmt target_25) {
	exists(PostfixIncrExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vip_1002)
}

predicate func_9(Parameter vwp_1003, Parameter vFrom14_1003, Parameter vip_1002, ArrayExpr target_9) {
		target_9.getArrayBase().(VariableAccess).getTarget()=vFrom14_1003
		and target_9.getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1002
		and target_9.getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_9.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_10(Parameter vwp_1003, VariableAccess target_10) {
		target_10.getTarget()=vwp_1003
}

predicate func_11(Parameter vip_1002, VariableAccess target_11) {
		target_11.getTarget()=vip_1002
}

predicate func_12(Parameter vwp_1003, VariableAccess target_12) {
		target_12.getTarget()=vwp_1003
}

predicate func_13(Parameter vip_1002, VariableAccess target_13) {
		target_13.getTarget()=vip_1002
}

predicate func_14(Parameter vstride_1002, Parameter vwp_1003, VariableAccess target_14) {
		target_14.getTarget()=vstride_1002
		and target_14.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
}

predicate func_15(Variable vmask_1005, VariableAccess target_15) {
		target_15.getTarget()=vmask_1005
}

predicate func_16(Parameter vn_1002, Parameter vip_1002, EqualityOperation target_39, ExprStmt target_16) {
		target_16.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vip_1002
		and target_16.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_1002
		and target_16.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand() instanceof Literal
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

/*predicate func_17(Parameter vn_1002, ExprStmt target_28, VariableAccess target_17) {
		target_17.getTarget()=vn_1002
		and target_28.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_17.getLocation())
}

*/
predicate func_18(Parameter vn_1002, Parameter vwp_1003, AssignPointerAddExpr target_18) {
		target_18.getLValue().(VariableAccess).getTarget()=vwp_1003
		and target_18.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_1002
		and target_18.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_19(Parameter vstride_1002, Parameter vwp_1003, AssignSubExpr target_19) {
		target_19.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_19.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_1002
		and target_19.getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_19.getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

/*predicate func_20(Parameter vwp_1003, VariableAccess target_20) {
		target_20.getTarget()=vwp_1003
		and target_20.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
predicate func_22(Parameter vstride_1002, Parameter vwp_1003, Variable vmask_1005, AssignAndExpr target_22) {
		target_22.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_22.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_1002
		and target_22.getRValue().(VariableAccess).getTarget()=vmask_1005
}

predicate func_23(Parameter vwp_1003, ExprStmt target_25, PostfixDecrExpr target_23) {
		target_23.getOperand().(VariableAccess).getTarget()=vwp_1003
		and target_23.getOperand().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_24(Parameter vip_1002, ExprStmt target_32, ExprStmt target_25, PostfixDecrExpr target_24) {
		target_24.getOperand().(VariableAccess).getTarget()=vip_1002
		and target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_24.getOperand().(VariableAccess).getLocation())
}

predicate func_25(Parameter vwp_1003, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_25.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
}

predicate func_26(Parameter vwp_1003, ExprStmt target_26) {
		target_26.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vwp_1003
}

predicate func_27(Parameter vip_1002, ExprStmt target_27) {
		target_27.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vip_1002
}

predicate func_28(Parameter vn_1002, ExprStmt target_28) {
		target_28.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vn_1002
		and target_28.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="4"
}

predicate func_30(Parameter vstride_1002, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstride_1002
}

predicate func_32(Parameter vwp_1003, Parameter vFrom14_1003, Parameter vip_1002, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFrom14_1003
		and target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1002
		and target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_32.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
}

predicate func_35(Parameter vFrom14_1003, Parameter vip_1002, ExprStmt target_35) {
		target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_35.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFrom14_1003
		and target_35.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_1002
		and target_35.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_35.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
}

predicate func_36(Parameter vwp_1003, Variable vmask_1005, ExprStmt target_36) {
		target_36.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_1003
		and target_36.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_36.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_36.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_36.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vmask_1005
}

predicate func_39(Parameter vstride_1002, EqualityOperation target_39) {
		target_39.getAnOperand().(VariableAccess).getTarget()=vstride_1002
		and target_39.getAnOperand().(Literal).getValue()="4"
}

from Function func, Parameter vn_1002, Parameter vstride_1002, Parameter vwp_1003, Parameter vFrom14_1003, Variable vmask_1005, Parameter vip_1002, Literal target_0, VariableAccess target_1, ArrayExpr target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, ExprStmt target_16, AssignPointerAddExpr target_18, AssignSubExpr target_19, AssignAndExpr target_22, PostfixDecrExpr target_23, PostfixDecrExpr target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_30, ExprStmt target_32, ExprStmt target_35, ExprStmt target_36, EqualityOperation target_39
where
func_0(vn_1002, target_28, target_0)
and func_1(vstride_1002, vwp_1003, target_30, target_32, target_1)
and not func_2(vwp_1003, target_25)
and not func_3(vip_1002, target_32, target_25)
and not func_4(vstride_1002, vwp_1003, vFrom14_1003, vmask_1005, target_30, target_35, target_32, target_36)
and not func_7(vwp_1003, target_25)
and not func_8(vip_1002, target_25)
and func_9(vwp_1003, vFrom14_1003, vip_1002, target_9)
and func_10(vwp_1003, target_10)
and func_11(vip_1002, target_11)
and func_12(vwp_1003, target_12)
and func_13(vip_1002, target_13)
and func_14(vstride_1002, vwp_1003, target_14)
and func_15(vmask_1005, target_15)
and func_16(vn_1002, vip_1002, target_39, target_16)
and func_18(vn_1002, vwp_1003, target_18)
and func_19(vstride_1002, vwp_1003, target_19)
and func_22(vstride_1002, vwp_1003, vmask_1005, target_22)
and func_23(vwp_1003, target_25, target_23)
and func_24(vip_1002, target_32, target_25, target_24)
and func_25(vwp_1003, target_25)
and func_26(vwp_1003, target_26)
and func_27(vip_1002, target_27)
and func_28(vn_1002, target_28)
and func_30(vstride_1002, target_30)
and func_32(vwp_1003, vFrom14_1003, vip_1002, target_32)
and func_35(vFrom14_1003, vip_1002, target_35)
and func_36(vwp_1003, vmask_1005, target_36)
and func_39(vstride_1002, target_39)
and vn_1002.getType().hasName("int")
and vstride_1002.getType().hasName("int")
and vwp_1003.getType().hasName("unsigned short *")
and vFrom14_1003.getType().hasName("uint16 *")
and vmask_1005.getType().hasName("int")
and vip_1002.getType().hasName("unsigned short *")
and vn_1002.getFunction() = func
and vstride_1002.getFunction() = func
and vwp_1003.getFunction() = func
and vFrom14_1003.getFunction() = func
and vmask_1005.(LocalVariable).getFunction() = func
and vip_1002.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
