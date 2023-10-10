/**
 * @name libtiff-9cfa5c469109c207bf3b916c52e618d4400ba2c0-invertImage
 * @id cpp/libtiff/9cfa5c469109c207bf3b916c52e618d4400ba2c0/invertImage
 * @description libtiff-9cfa5c469109c207bf3b916c52e618d4400ba2c0-tools/tiffcrop.c-invertImage CVE-2020-19131
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsrc_uint32_9150) {
	exists(ComplementExpr target_0 |
		target_0.getOperand() instanceof PointerDereferenceExpr
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_uint32_9150)
}

predicate func_1(Variable vsrc_uint16_9149) {
	exists(ComplementExpr target_1 |
		target_1.getOperand() instanceof PointerDereferenceExpr
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_uint16_9149)
}

predicate func_2(Variable vsrc_9148, PointerDereferenceExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue() instanceof SubExpr
}

predicate func_3(Variable vsrc_9148, PostfixIncrExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vsrc_9148
}

predicate func_4(Variable vsrc_uint32_9150, PointerDereferenceExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vsrc_uint32_9150
}

predicate func_5(Variable vsrc_uint16_9149, PointerDereferenceExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vsrc_uint16_9149
}

predicate func_6(Variable vsrc_9148, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_6.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
}

predicate func_7(Variable vcol_9146, VariableAccess target_7) {
		target_7.getTarget()=vcol_9146
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue() instanceof Literal
}

predicate func_8(Parameter vbps_9144, VariableAccess target_8) {
		target_8.getTarget()=vbps_9144
}

predicate func_9(Function func, DeclStmt target_9) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Variable vsrc_uint32_9150, SubExpr target_10) {
		target_10.getLeftOperand().(HexLiteral).getValue()="4294967295"
		and target_10.getRightOperand() instanceof PointerDereferenceExpr
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_uint32_9150
}

predicate func_11(Variable vsrc_uint16_9149, SubExpr target_11) {
		target_11.getLeftOperand().(HexLiteral).getValue()="65535"
		and target_11.getRightOperand() instanceof PointerDereferenceExpr
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_uint16_9149
}

predicate func_12(Variable vcol_9146, PostfixIncrExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vcol_9146
}

predicate func_13(Variable vsrc_9148, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_13.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="255"
		and target_13.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
}

predicate func_14(Function func, ExprStmt target_14) {
		target_14.getExpr() instanceof PostfixIncrExpr
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Parameter vwidth_9144, Parameter vlength_9144, Variable vrow_9146, Variable vcol_9146, Variable vbytebuff1_9147, Variable vbytebuff2_9147, Variable vsrc_9148, VariableAccess target_33, ForStmt target_15) {
		target_15.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrow_9146
		and target_15.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_15.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrow_9146
		and target_15.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_9144
		and target_15.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vrow_9146
		and target_15.getStmt().(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcol_9146
		and target_15.getStmt().(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_15.getStmt().(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcol_9146
		and target_15.getStmt().(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth_9144
		and target_15.getStmt().(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcol_9146
		and target_15.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff1_9147
		and target_15.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="16"
		and target_15.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff2_9147
		and target_15.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="16"
		and target_15.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_15.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vbytebuff2_9147
		and target_15.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_15.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_33
}

/*predicate func_16(Variable vbytebuff1_9147, Variable vsrc_9148, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff1_9147
		and target_16.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="16"
		and target_16.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_16.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="15"
}

*/
/*predicate func_17(Variable vbytebuff2_9147, Variable vsrc_9148, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff2_9147
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="16"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="15"
}

*/
predicate func_18(Variable vbytebuff1_9147, Variable vbytebuff2_9147, Variable vsrc_9148, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_18.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vbytebuff1_9147
		and target_18.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_18.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vbytebuff2_9147
}

/*predicate func_19(Variable vsrc_9148, ExprStmt target_18, ExprStmt target_22, ExprStmt target_19) {
		target_19.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_18.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_19.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_19.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

*/
predicate func_20(VariableAccess target_33, Function func, BreakStmt target_20) {
		target_20.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_33
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Parameter vwidth_9144, Parameter vlength_9144, Variable vrow_9146, Variable vcol_9146, Variable vbytebuff1_9147, Variable vbytebuff2_9147, Variable vbytebuff3_9147, Variable vbytebuff4_9147, Variable vsrc_9148, VariableAccess target_33, ForStmt target_21) {
		target_21.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrow_9146
		and target_21.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrow_9146
		and target_21.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_9144
		and target_21.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vrow_9146
		and target_21.getStmt().(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcol_9146
		and target_21.getStmt().(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_21.getStmt().(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcol_9146
		and target_21.getStmt().(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth_9144
		and target_21.getStmt().(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcol_9146
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff1_9147
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff2_9147
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff3_9147
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff4_9147
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(VariableAccess).getTarget()=vbytebuff4_9147
		and target_21.getStmt().(ForStmt).getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_21.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_33
}

predicate func_22(Variable vbytebuff1_9147, Variable vsrc_9148, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff1_9147
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_22.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="3"
}

/*predicate func_23(Variable vbytebuff2_9147, Variable vsrc_9148, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff2_9147
		and target_23.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_23.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_23.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="3"
}

*/
/*predicate func_24(Variable vbytebuff3_9147, Variable vsrc_9148, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff3_9147
		and target_24.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_24.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_24.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="3"
}

*/
/*predicate func_25(Variable vbytebuff4_9147, Variable vsrc_9148, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytebuff4_9147
		and target_25.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_25.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_25.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="3"
}

*/
/*predicate func_26(Variable vbytebuff1_9147, Variable vbytebuff2_9147, Variable vbytebuff3_9147, Variable vbytebuff4_9147, Variable vsrc_9148, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
		and target_26.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vbytebuff1_9147
		and target_26.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and target_26.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vbytebuff2_9147
		and target_26.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_26.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vbytebuff3_9147
		and target_26.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_26.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(VariableAccess).getTarget()=vbytebuff4_9147
}

*/
/*predicate func_27(Variable vsrc_9148, ExprStmt target_27) {
		target_27.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_9148
}

*/
predicate func_29(Parameter vbps_9144, Parameter vwidth_9144, Parameter vlength_9144, Variable vrow_9146, Variable vcol_9146, Parameter vspp_9144, ForStmt target_29) {
		target_29.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrow_9146
		and target_29.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_29.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrow_9146
		and target_29.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_9144
		and target_29.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vrow_9146
		and target_29.getStmt().(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcol_9146
		and target_29.getStmt().(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_29.getStmt().(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcol_9146
		and target_29.getStmt().(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth_9144
		and target_29.getStmt().(ForStmt).getUpdate().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vcol_9146
		and target_29.getStmt().(ForStmt).getUpdate().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(Literal).getValue()="8"
		and target_29.getStmt().(ForStmt).getUpdate().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vspp_9144
		and target_29.getStmt().(ForStmt).getUpdate().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbps_9144
		and target_29.getStmt().(ForStmt).getStmt() instanceof BlockStmt
}

/*predicate func_30(Variable vcol_9146, VariableAccess target_30) {
		target_30.getTarget()=vcol_9146
}

*/
/*predicate func_31(Parameter vbps_9144, Parameter vspp_9144, MulExpr target_31) {
		target_31.getLeftOperand().(VariableAccess).getTarget()=vspp_9144
		and target_31.getRightOperand().(VariableAccess).getTarget()=vbps_9144
}

*/
predicate func_33(Parameter vbps_9144, VariableAccess target_33) {
		target_33.getTarget()=vbps_9144
}

from Function func, Parameter vbps_9144, Parameter vwidth_9144, Parameter vlength_9144, Variable vrow_9146, Variable vcol_9146, Variable vbytebuff1_9147, Variable vbytebuff2_9147, Variable vbytebuff3_9147, Variable vbytebuff4_9147, Variable vsrc_9148, Variable vsrc_uint16_9149, Variable vsrc_uint32_9150, Parameter vspp_9144, PointerDereferenceExpr target_2, PostfixIncrExpr target_3, PointerDereferenceExpr target_4, PointerDereferenceExpr target_5, BlockStmt target_6, VariableAccess target_7, VariableAccess target_8, DeclStmt target_9, SubExpr target_10, SubExpr target_11, PostfixIncrExpr target_12, ExprStmt target_13, ExprStmt target_14, ForStmt target_15, ExprStmt target_18, BreakStmt target_20, ForStmt target_21, ExprStmt target_22, ForStmt target_29, VariableAccess target_33
where
not func_0(vsrc_uint32_9150)
and not func_1(vsrc_uint16_9149)
and func_2(vsrc_9148, target_2)
and func_3(vsrc_9148, target_3)
and func_4(vsrc_uint32_9150, target_4)
and func_5(vsrc_uint16_9149, target_5)
and func_6(vsrc_9148, target_6)
and func_7(vcol_9146, target_7)
and func_8(vbps_9144, target_8)
and func_9(func, target_9)
and func_10(vsrc_uint32_9150, target_10)
and func_11(vsrc_uint16_9149, target_11)
and func_12(vcol_9146, target_12)
and func_13(vsrc_9148, target_13)
and func_14(func, target_14)
and func_15(vwidth_9144, vlength_9144, vrow_9146, vcol_9146, vbytebuff1_9147, vbytebuff2_9147, vsrc_9148, target_33, target_15)
and func_18(vbytebuff1_9147, vbytebuff2_9147, vsrc_9148, target_18)
and func_20(target_33, func, target_20)
and func_21(vwidth_9144, vlength_9144, vrow_9146, vcol_9146, vbytebuff1_9147, vbytebuff2_9147, vbytebuff3_9147, vbytebuff4_9147, vsrc_9148, target_33, target_21)
and func_22(vbytebuff1_9147, vsrc_9148, target_22)
and func_29(vbps_9144, vwidth_9144, vlength_9144, vrow_9146, vcol_9146, vspp_9144, target_29)
and func_33(vbps_9144, target_33)
and vbps_9144.getType().hasName("uint16")
and vwidth_9144.getType().hasName("uint32")
and vlength_9144.getType().hasName("uint32")
and vrow_9146.getType().hasName("uint32")
and vcol_9146.getType().hasName("uint32")
and vbytebuff1_9147.getType().hasName("unsigned char")
and vbytebuff2_9147.getType().hasName("unsigned char")
and vbytebuff3_9147.getType().hasName("unsigned char")
and vbytebuff4_9147.getType().hasName("unsigned char")
and vsrc_9148.getType().hasName("unsigned char *")
and vsrc_uint16_9149.getType().hasName("uint16 *")
and vsrc_uint32_9150.getType().hasName("uint32 *")
and vspp_9144.getType().hasName("uint16")
and vbps_9144.getFunction() = func
and vwidth_9144.getFunction() = func
and vlength_9144.getFunction() = func
and vrow_9146.(LocalVariable).getFunction() = func
and vcol_9146.(LocalVariable).getFunction() = func
and vbytebuff1_9147.(LocalVariable).getFunction() = func
and vbytebuff2_9147.(LocalVariable).getFunction() = func
and vbytebuff3_9147.(LocalVariable).getFunction() = func
and vbytebuff4_9147.(LocalVariable).getFunction() = func
and vsrc_9148.(LocalVariable).getFunction() = func
and vsrc_uint16_9149.(LocalVariable).getFunction() = func
and vsrc_uint32_9150.(LocalVariable).getFunction() = func
and vspp_9144.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
