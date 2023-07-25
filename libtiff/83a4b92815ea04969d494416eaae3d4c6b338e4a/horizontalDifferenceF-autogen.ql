/**
 * @name libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-horizontalDifferenceF
 * @id cpp/libtiff/83a4b92815ea04969d494416eaae3d4c6b338e4a/horizontalDifferenceF
 * @description libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-libtiff/tif_pixarlog.c-horizontalDifferenceF CVE-2016-9533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Parameter vn_945, ExprStmt target_30, VariableAccess target_0) {
		target_0.getTarget()=vn_945
		and vn_945.getIndex() = 1
		and target_30.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

*/
predicate func_1(Parameter vn_945, ExprStmt target_30, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="2047"
		and target_1.getParent().(SubExpr).getParent().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_945
		and target_30.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getParent().(SubExpr).getParent().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
}

predicate func_2(Parameter vn_945, ExprStmt target_20, ExprStmt target_33, VariableAccess target_2) {
		target_2.getTarget()=vn_945
		and vn_945.getIndex() = 1
		and target_20.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getLocation())
		and target_2.getLocation().isBefore(target_33.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_3(Parameter vstride_945, Parameter vwp_945, ExprStmt target_34, ExprStmt target_36, VariableAccess target_3) {
		target_3.getTarget()=vwp_945
		and vwp_945.getIndex() = 3
		and target_3.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_945
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_3.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_36.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getLocation())
}

predicate func_4(Parameter vwp_945, ExprStmt target_27) {
	exists(PostfixIncrExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vwp_945
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vip_945, ExprStmt target_27) {
	exists(PostfixIncrExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vip_945)
}

predicate func_6(Parameter vip_945, Parameter vstride_945, Parameter vwp_945, Variable vmask_947, Variable vfltsize_948, ExprStmt target_20, ExprStmt target_34, ExprStmt target_39, ExprStmt target_36, ExprStmt target_27) {
	exists(BitwiseAndExpr target_6 |
		target_6.getLeftOperand().(SubExpr).getLeftOperand() instanceof ConditionalExpr
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vstride_945
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0.0"
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getThen() instanceof Literal
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2.0"
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("uint16 *")
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vfltsize_948
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="24.19999999999999929"
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="2047"
		and target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="0.5"
		and target_6.getRightOperand().(VariableAccess).getTarget()=vmask_947
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_6.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_39.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getRightOperand().(VariableAccess).getLocation())
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(SubExpr).getRightOperand().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

/*predicate func_7(Parameter vip_945, Parameter vstride_945, Variable vfltsize_948, Variable vLogK1, ExprStmt target_20, ExprStmt target_34, ExprStmt target_40, ExprStmt target_36, ExprStmt target_27) {
	exists(ConditionalExpr target_7 |
		target_7.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vstride_945
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0.0"
		and target_7.getThen() instanceof Literal
		and target_7.getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_7.getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vstride_945
		and target_7.getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2.0"
		and target_7.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("uint16 *")
		and target_7.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_7.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_7.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vfltsize_948
		and target_7.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_7.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_7.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="24.19999999999999929"
		and target_7.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="2047"
		and target_7.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vLogK1
		and target_7.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("log")
		and target_7.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="0.5"
		and target_20.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation().isBefore(target_40.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getLocation())
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_8(Parameter vip_945, Parameter vwp_945, Variable vfltsize_948, MulExpr target_42, ExprStmt target_36, ExprStmt target_27) {
	exists(MulExpr target_8 |
		target_8.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_8.getLeftOperand().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_8.getRightOperand().(VariableAccess).getTarget()=vfltsize_948
		and target_8.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_42.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_8.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getRightOperand().(VariableAccess).getLocation()))
}

*/
predicate func_9(Parameter vwp_945, ExprStmt target_27) {
	exists(PostfixIncrExpr target_9 |
		target_9.getOperand().(VariableAccess).getTarget()=vwp_945
		and target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_9.getOperand().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vip_945, MulExpr target_44) {
	exists(PostfixIncrExpr target_10 |
		target_10.getOperand().(VariableAccess).getTarget()=vip_945
		and target_44.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation()))
}

predicate func_11(Parameter vip_945, Parameter vwp_945, Parameter vFromLT2_945, Variable vfltsize_948, Variable vLogK1, ConditionalExpr target_11) {
		target_11.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_11.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_11.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0.0"
		and target_11.getThen().(Literal).getValue()="0"
		and target_11.getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_11.getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_11.getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2.0"
		and target_11.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFromLT2_945
		and target_11.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_11.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_11.getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vfltsize_948
		and target_11.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_11.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_11.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="24.19999999999999929"
		and target_11.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="2047"
		and target_11.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vLogK1
		and target_11.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("log")
		and target_11.getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="0.5"
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_11.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_12(Parameter vwp_945, VariableAccess target_12) {
		target_12.getTarget()=vwp_945
}

predicate func_13(Parameter vip_945, VariableAccess target_13) {
		target_13.getTarget()=vip_945
}

predicate func_14(Parameter vwp_945, VariableAccess target_14) {
		target_14.getTarget()=vwp_945
}

predicate func_15(Parameter vip_945, VariableAccess target_15) {
		target_15.getTarget()=vip_945
}

predicate func_16(Parameter vstride_945, Parameter vwp_945, VariableAccess target_16) {
		target_16.getTarget()=vstride_945
		and target_16.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
}

predicate func_18(Parameter vstride_945, Parameter vwp_945, VariableAccess target_18) {
		target_18.getTarget()=vstride_945
		and target_18.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
}

predicate func_19(Variable vmask_947, VariableAccess target_19) {
		target_19.getTarget()=vmask_947
}

predicate func_20(Parameter vip_945, Parameter vn_945, EqualityOperation target_45, ExprStmt target_20) {
		target_20.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vip_945
		and target_20.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_945
		and target_20.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand() instanceof Literal
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
}

predicate func_21(Parameter vn_945, Parameter vwp_945, AssignPointerAddExpr target_21) {
		target_21.getLValue().(VariableAccess).getTarget()=vwp_945
		and target_21.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_945
		and target_21.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_22(Parameter vstride_945, Parameter vwp_945, AssignSubExpr target_22) {
		target_22.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_22.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_945
		and target_22.getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_22.getRValue().(ArrayExpr).getArrayOffset() instanceof Literal
}

/*predicate func_23(Parameter vwp_945, VariableAccess target_23) {
		target_23.getTarget()=vwp_945
		and target_23.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

*/
predicate func_24(Parameter vstride_945, Parameter vwp_945, Variable vmask_947, AssignAndExpr target_24) {
		target_24.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_24.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstride_945
		and target_24.getRValue().(VariableAccess).getTarget()=vmask_947
}

predicate func_25(Parameter vwp_945, ExprStmt target_27, PostfixDecrExpr target_25) {
		target_25.getOperand().(VariableAccess).getTarget()=vwp_945
		and target_25.getOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_26(Parameter vip_945, ExprStmt target_27, PostfixDecrExpr target_26) {
		target_26.getOperand().(VariableAccess).getTarget()=vip_945
}

predicate func_27(Parameter vwp_945, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_27.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_27.getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
}

predicate func_28(Parameter vwp_945, ExprStmt target_28) {
		target_28.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vwp_945
}

predicate func_29(Parameter vip_945, ExprStmt target_29) {
		target_29.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vip_945
}

predicate func_30(Parameter vn_945, ExprStmt target_30) {
		target_30.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vn_945
		and target_30.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="4"
}

predicate func_33(Parameter vn_945, Parameter vstride_945, ExprStmt target_33) {
		target_33.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vn_945
		and target_33.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vstride_945
}

predicate func_34(Parameter vstride_945, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstride_945
}

predicate func_36(Parameter vip_945, Parameter vwp_945, Parameter vFromLT2_945, Variable vfltsize_948, ExprStmt target_36) {
		target_36.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_36.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0.0"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2.0"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vFromLT2_945
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vfltsize_948
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="24.19999999999999929"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="2047"
		and target_36.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(Literal).getValue()="0.5"
}

predicate func_39(Parameter vwp_945, Variable vmask_947, ExprStmt target_39) {
		target_39.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwp_945
		and target_39.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_39.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int32")
		and target_39.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int32")
		and target_39.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vmask_947
}

predicate func_40(Parameter vn_945, Parameter vstride_945, ExprStmt target_40) {
		target_40.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vn_945
		and target_40.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vstride_945
}

predicate func_42(Parameter vip_945, MulExpr target_42) {
		target_42.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_42.getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_42.getRightOperand().(VariableAccess).getTarget().getType().hasName("float")
}

predicate func_44(Parameter vip_945, MulExpr target_44) {
		target_44.getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vip_945
		and target_44.getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_44.getRightOperand().(VariableAccess).getTarget().getType().hasName("float")
}

predicate func_45(Parameter vstride_945, EqualityOperation target_45) {
		target_45.getAnOperand().(VariableAccess).getTarget()=vstride_945
		and target_45.getAnOperand().(Literal).getValue()="4"
}

from Function func, Parameter vip_945, Parameter vn_945, Parameter vstride_945, Parameter vwp_945, Parameter vFromLT2_945, Variable vmask_947, Variable vfltsize_948, Variable vLogK1, Literal target_1, VariableAccess target_2, VariableAccess target_3, ConditionalExpr target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, VariableAccess target_16, VariableAccess target_18, VariableAccess target_19, ExprStmt target_20, AssignPointerAddExpr target_21, AssignSubExpr target_22, AssignAndExpr target_24, PostfixDecrExpr target_25, PostfixDecrExpr target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_33, ExprStmt target_34, ExprStmt target_36, ExprStmt target_39, ExprStmt target_40, MulExpr target_42, MulExpr target_44, EqualityOperation target_45
where
func_1(vn_945, target_30, target_1)
and func_2(vn_945, target_20, target_33, target_2)
and func_3(vstride_945, vwp_945, target_34, target_36, target_3)
and not func_4(vwp_945, target_27)
and not func_5(vip_945, target_27)
and not func_6(vip_945, vstride_945, vwp_945, vmask_947, vfltsize_948, target_20, target_34, target_39, target_36, target_27)
and not func_9(vwp_945, target_27)
and not func_10(vip_945, target_44)
and func_11(vip_945, vwp_945, vFromLT2_945, vfltsize_948, vLogK1, target_11)
and func_12(vwp_945, target_12)
and func_13(vip_945, target_13)
and func_14(vwp_945, target_14)
and func_15(vip_945, target_15)
and func_16(vstride_945, vwp_945, target_16)
and func_18(vstride_945, vwp_945, target_18)
and func_19(vmask_947, target_19)
and func_20(vip_945, vn_945, target_45, target_20)
and func_21(vn_945, vwp_945, target_21)
and func_22(vstride_945, vwp_945, target_22)
and func_24(vstride_945, vwp_945, vmask_947, target_24)
and func_25(vwp_945, target_27, target_25)
and func_26(vip_945, target_27, target_26)
and func_27(vwp_945, target_27)
and func_28(vwp_945, target_28)
and func_29(vip_945, target_29)
and func_30(vn_945, target_30)
and func_33(vn_945, vstride_945, target_33)
and func_34(vstride_945, target_34)
and func_36(vip_945, vwp_945, vFromLT2_945, vfltsize_948, target_36)
and func_39(vwp_945, vmask_947, target_39)
and func_40(vn_945, vstride_945, target_40)
and func_42(vip_945, target_42)
and func_44(vip_945, target_44)
and func_45(vstride_945, target_45)
and vip_945.getType().hasName("float *")
and vn_945.getType().hasName("int")
and vstride_945.getType().hasName("int")
and vwp_945.getType().hasName("uint16 *")
and vFromLT2_945.getType().hasName("uint16 *")
and vmask_947.getType().hasName("int32")
and vfltsize_948.getType().hasName("float")
and vLogK1.getType().hasName("float")
and vip_945.getFunction() = func
and vn_945.getFunction() = func
and vstride_945.getFunction() = func
and vwp_945.getFunction() = func
and vFromLT2_945.getFunction() = func
and vmask_947.(LocalVariable).getFunction() = func
and vfltsize_948.(LocalVariable).getFunction() = func
and not vLogK1.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
