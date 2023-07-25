/**
 * @name ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-msrle_decode_8_16_24_32
 * @id cpp/ffmpeg/327ff82bac3081d918dceb4931c77e25d0a1480d/msrle-decode-8-16-24-32
 * @description ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-libavcodec/msrledec.c-msrle_decode_8_16_24_32 CVE-2013-2496
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Next line is beyond picture bounds\n"
		and not target_0.getValue()="bytestream overrun\n"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vsrcsize_132, LogicalAndExpr target_52, VariableAccess target_1) {
		target_1.getTarget()=vsrcsize_132
		and vsrcsize_132.getIndex() = 4
		and target_1.getLocation().isBefore(target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="4"
		and not target_2.getValue()="0"
		and target_2.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="2"
		and not target_3.getValue()="0"
		and target_3.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="4"
		and not target_4.getValue()="16"
		and target_4.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_5.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_5.getLesserOperand().(Literal).getValue()="0"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vp1_136) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("bytestream2_get_byteu")
		and target_6.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp1_136)
}

predicate func_7(Variable vp2_136) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("bytestream2_get_byte")
		and target_7.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp2_136)
}

predicate func_8(Parameter vavctx_131, LogicalAndExpr target_52, ExprStmt target_75, ExprStmt target_76) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("bytestream2_get_be16")
		and target_8.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_8.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_8.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_131
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Next line is beyond picture bounds (%d bytes left)\n"
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_8.getElse().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_52
		and target_75.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_9(Function func) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("bytestream2_get_be16")
		and target_9.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_9.getEnclosingFunction() = func)
}

*/
/*predicate func_10(EqualityOperation target_77, Function func) {
	exists(ReturnStmt target_10 |
		target_10.getExpr().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_77
		and target_10.getEnclosingFunction() = func)
}

*/
/*predicate func_11(Parameter vavctx_131, ExprStmt target_75, ExprStmt target_76) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("av_log")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vavctx_131
		and target_11.getArgument(1).(Literal).getValue()="16"
		and target_11.getArgument(2).(StringLiteral).getValue()="Next line is beyond picture bounds (%d bytes left)\n"
		and target_11.getArgument(3).(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_11.getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_75.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getArgument(0).(VariableAccess).getLocation())
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_12(Function func) {
	exists(UnaryMinusExpr target_12 |
		target_12.getValue()="3199971767"
		and target_12.getEnclosingFunction() = func)
}

*/
predicate func_13(Variable vp1_136) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("bytestream2_get_byte")
		and target_13.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_13.getParent().(AssignExpr).getRValue() = target_13
		and target_13.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp1_136)
}

predicate func_14(Variable vp2_136) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("bytestream2_get_byte")
		and target_14.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_14.getParent().(AssignExpr).getRValue() = target_14
		and target_14.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp2_136)
}

predicate func_15(Function func) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("bytestream2_skip")
		and target_15.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_15.getArgument(1).(MulExpr).getLeftOperand() instanceof Literal
		and target_15.getArgument(1).(MulExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_15.getArgument(1).(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Variable vsrc_135) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("bytestream2_get_bytes_left")
		and target_16.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_16.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vsrc_135
		and target_16.getParent().(LTExpr).getGreaterOperand() instanceof PointerArithmeticOperation)
}

predicate func_17(EqualityOperation target_32, Function func) {
	exists(ReturnStmt target_17 |
		target_17.getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_17
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Variable voutput_134) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("bytestream2_get_byteu")
		and target_18.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_18.getParent().(AssignExpr).getRValue() = target_18
		and target_18.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutput_134)
}

predicate func_19(Function func) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("bytestream2_skip")
		and target_19.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_19.getArgument(1) instanceof Literal
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Variable voutput_134, Variable vsrc_135, ExprStmt target_78, ExprStmt target_33) {
	exists(PointerDereferenceExpr target_20 |
		target_20.getOperand().(VariableAccess).getTarget()=voutput_134
		and target_20.getParent().(AssignExpr).getLValue() = target_20
		and target_20.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_20.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
		and target_78.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_20.getOperand().(VariableAccess).getLocation())
		and target_20.getOperand().(VariableAccess).getLocation().isBefore(target_33.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_21(Variable vpix16_137) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("bytestream2_get_le16u")
		and target_21.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_21.getParent().(AssignExpr).getRValue() = target_21
		and target_21.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix16_137)
}

predicate func_22(Variable voutput_134, Variable vp2_136, Variable vi_136, EqualityOperation target_32, ExprStmt target_35, LogicalOrExpr target_79, RelationalOperation target_80, ExprStmt target_81, PostfixIncrExpr target_82) {
	exists(IfStmt target_22 |
		target_22.getCondition() instanceof EqualityOperation
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_136
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_136
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp2_136
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_136
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_le32u")
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=voutput_134
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="4"
		and target_22.getParent().(IfStmt).getParent().(IfStmt).getElse().(IfStmt).getElse()=target_22
		and target_22.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_32
		and target_35.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_80.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_81.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation())
		and target_82.getOperand().(VariableAccess).getLocation().isBefore(target_22.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

/*predicate func_23(Variable voutput_134, Variable vsrc_135, ExprStmt target_83, ExprStmt target_35) {
	exists(PointerDereferenceExpr target_23 |
		target_23.getOperand().(VariableAccess).getTarget()=voutput_134
		and target_23.getParent().(AssignExpr).getLValue() = target_23
		and target_23.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_23.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
		and target_83.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_23.getOperand().(VariableAccess).getLocation())
		and target_23.getOperand().(VariableAccess).getLocation().isBefore(target_35.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_24(Variable vpix32_138) {
	exists(FunctionCall target_24 |
		target_24.getTarget().hasName("bytestream2_get_le32u")
		and target_24.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_24.getParent().(AssignExpr).getRValue() = target_24
		and target_24.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix32_138)
}

*/
predicate func_25(Variable vpix_200) {
	exists(FunctionCall target_25 |
		target_25.getTarget().hasName("bytestream2_get_byte")
		and target_25.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_25.getParent().(AssignExpr).getRValue() = target_25
		and target_25.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_25.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_26(Variable vpix16_137) {
	exists(FunctionCall target_26 |
		target_26.getTarget().hasName("bytestream2_get_le16")
		and target_26.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_26.getParent().(AssignExpr).getRValue() = target_26
		and target_26.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix16_137)
}

predicate func_27(Variable vpix_200) {
	exists(FunctionCall target_27 |
		target_27.getTarget().hasName("bytestream2_get_byte")
		and target_27.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_27.getParent().(AssignExpr).getRValue() = target_27
		and target_27.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_27.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_28(Variable vpix_200) {
	exists(FunctionCall target_28 |
		target_28.getTarget().hasName("bytestream2_get_byte")
		and target_28.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_28.getParent().(AssignExpr).getRValue() = target_28
		and target_28.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_28.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_29(Variable vpix_200) {
	exists(FunctionCall target_29 |
		target_29.getTarget().hasName("bytestream2_get_byte")
		and target_29.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_29.getParent().(AssignExpr).getRValue() = target_29
		and target_29.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_29.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2")
}

predicate func_30(Variable vpix32_138) {
	exists(FunctionCall target_30 |
		target_30.getTarget().hasName("bytestream2_get_le32")
		and target_30.getArgument(0).(VariableAccess).getType().hasName("GetByteContext *")
		and target_30.getParent().(AssignExpr).getRValue() = target_30
		and target_30.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix32_138)
}

predicate func_31(Function func, UnaryMinusExpr target_31) {
		target_31.getValue()="-1"
		and target_31.getEnclosingFunction() = func
}

predicate func_32(Parameter vdepth_131, EqualityOperation target_32) {
		target_32.getAnOperand().(VariableAccess).getTarget()=vdepth_131
		and target_32.getAnOperand().(Literal).getValue()="16"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ForStmt
}

predicate func_33(Variable voutput_134, Variable vpix16_137, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voutput_134
		and target_33.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpix16_137
}

predicate func_34(Parameter vdepth_131, EqualityOperation target_34) {
		target_34.getAnOperand().(VariableAccess).getTarget()=vdepth_131
		and target_34.getAnOperand().(Literal).getValue()="32"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ForStmt
}

predicate func_35(Variable voutput_134, Variable vpix32_138, ExprStmt target_35) {
		target_35.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voutput_134
		and target_35.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpix32_138
}

predicate func_36(Variable vline_136, BlockStmt target_84, RelationalOperation target_36) {
		 (target_36 instanceof GTExpr or target_36 instanceof LTExpr)
		and target_36.getLesserOperand().(VariableAccess).getTarget()=vline_136
		and target_36.getGreaterOperand().(Literal).getValue()="0"
		and target_36.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_36.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_84
}

predicate func_37(Parameter vdepth_131, Variable vp2_136, MulExpr target_37) {
		target_37.getLeftOperand().(VariableAccess).getTarget()=vp2_136
		and target_37.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdepth_131
		and target_37.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
}

predicate func_38(EqualityOperation target_77, Function func, DeclStmt target_38) {
		target_38.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_77
		and target_38.getEnclosingFunction() = func
}

predicate func_39(Parameter vpic_131, Variable voutput_134, Variable voutput_end_134, Variable vp1_136, EqualityOperation target_77, IfStmt target_39) {
		target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpic_131
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_134
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vp1_136
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voutput_end_134
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpic_131
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_134
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vp1_136
		and target_39.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voutput_end_134
		and target_39.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_77
}

predicate func_40(Variable vp1_136, Variable vpos_136, EqualityOperation target_77, ExprStmt target_40) {
		target_40.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vpos_136
		and target_40.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vp1_136
		and target_40.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_77
}

predicate func_41(Parameter vdepth_131, Variable vp1_136, Variable vi_136, EqualityOperation target_77, ForStmt target_41) {
		target_41.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_136
		and target_41.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_41.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_136
		and target_41.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp1_136
		and target_41.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_136
		and target_41.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(VariableAccess).getTarget()=vdepth_131
		and target_41.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="8"
		and target_41.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="16"
		and target_41.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(7).(SwitchCase).getExpr().(Literal).getValue()="24"
		and target_41.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(12).(SwitchCase).getExpr().(Literal).getValue()="32"
		and target_41.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_77
}

predicate func_43(Variable vsrc_135, Variable vpix16_137, VariableAccess target_43) {
		target_43.getTarget()=vpix16_137
		and target_43.getParent().(AssignExpr).getLValue() = target_43
		and target_43.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_43.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
}

predicate func_44(Variable vsrc_135, Variable vpix32_138, VariableAccess target_44) {
		target_44.getTarget()=vpix32_138
		and target_44.getParent().(AssignExpr).getLValue() = target_44
		and target_44.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_44.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
}

predicate func_47(Function func, DeclStmt target_47) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_47
}

predicate func_48(Parameter vdata_132, Parameter vsrcsize_132, Variable vsrc_135, LogicalAndExpr target_52, VariableAccess target_48) {
		target_48.getTarget()=vsrc_135
		and target_48.getParent().(LTExpr).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_132
		and target_48.getParent().(LTExpr).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsrcsize_132
		and target_48.getParent().(LTExpr).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

/*predicate func_49(Parameter vdata_132, Parameter vsrcsize_132, LogicalAndExpr target_52, PointerArithmeticOperation target_49) {
		target_49.getAnOperand().(VariableAccess).getTarget()=vdata_132
		and target_49.getAnOperand().(VariableAccess).getTarget()=vsrcsize_132
		and target_49.getAnOperand().(VariableAccess).getLocation().isBefore(target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_50(Variable vsrc_135, Variable vp1_136, RelationalOperation target_86, EqualityOperation target_77, PointerDereferenceExpr target_50) {
		target_50.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_50.getParent().(AssignExpr).getRValue() = target_50
		and target_50.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp1_136
		and target_86.getLesserOperand().(VariableAccess).getLocation().isBefore(target_50.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_50.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_77.getAnOperand().(VariableAccess).getLocation())
}

predicate func_51(Variable vsrc_135, Variable vp2_136, LogicalAndExpr target_52, EqualityOperation target_89, PointerDereferenceExpr target_51) {
		target_51.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_51.getParent().(AssignExpr).getRValue() = target_51
		and target_51.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp2_136
		and target_51.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_51.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_89.getAnOperand().(VariableAccess).getLocation())
}

predicate func_52(Parameter vdata_132, Parameter vsrcsize_132, Variable vsrc_135, BlockStmt target_84, LogicalAndExpr target_52) {
		target_52.getAnOperand() instanceof RelationalOperation
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsrc_135
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_132
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsrcsize_132
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("av_bswap16")
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="l"
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_52.getParent().(IfStmt).getThen()=target_84
}

/*predicate func_53(Variable vsrc_135, FunctionCall target_53) {
		target_53.getTarget().hasName("av_bswap16")
		and target_53.getArgument(0).(PointerFieldAccess).getTarget().getName()="l"
		and target_53.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
}

*/
predicate func_54(Variable vsrc_135, Variable vp1_136, LogicalAndExpr target_52, EqualityOperation target_77, ExprStmt target_91, PointerDereferenceExpr target_54) {
		target_54.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_54.getParent().(AssignExpr).getRValue() = target_54
		and target_54.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp1_136
		and target_52.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_54.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_77.getAnOperand().(VariableAccess).getLocation().isBefore(target_54.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_54.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_91.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_55(Variable vsrc_135, Variable vp2_136, EqualityOperation target_94, ExprStmt target_95, PointerDereferenceExpr target_55) {
		target_55.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_55.getParent().(AssignExpr).getRValue() = target_55
		and target_55.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp2_136
		and target_94.getAnOperand().(VariableAccess).getLocation().isBefore(target_55.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_55.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_95.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_56(Variable vsrc_135, AssignPointerAddExpr target_56) {
		target_56.getLValue().(VariableAccess).getTarget()=vsrc_135
		and target_56.getRValue() instanceof MulExpr
}

predicate func_57(Variable voutput_134, Variable vsrc_135, LogicalOrExpr target_96, PointerDereferenceExpr target_57) {
		target_57.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_57.getParent().(AssignExpr).getRValue() = target_57
		and target_57.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutput_134
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_57.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_58(Variable vsrc_135, ExprStmt target_78, ExprStmt target_99, PostfixIncrExpr target_58) {
		target_58.getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_58.getOperand().(VariableAccess).getLocation().isBefore(target_99.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_59(Variable vsrc_135, PointerFieldAccess target_59) {
		target_59.getTarget().getName()="l"
		and target_59.getQualifier().(VariableAccess).getTarget()=vsrc_135
}

predicate func_60(Variable vsrc_135, ExprStmt target_99, ExprStmt target_102, AssignPointerAddExpr target_60) {
		target_60.getLValue().(VariableAccess).getTarget()=vsrc_135
		and target_60.getRValue() instanceof Literal
		and target_99.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_60.getLValue().(VariableAccess).getLocation())
		and target_60.getLValue().(VariableAccess).getLocation().isBefore(target_102.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_61(Variable vsrc_135, PointerFieldAccess target_61) {
		target_61.getTarget().getName()="l"
		and target_61.getQualifier().(VariableAccess).getTarget()=vsrc_135
}

predicate func_62(Variable vsrc_135, ExprStmt target_102, AssignPointerAddExpr target_62) {
		target_62.getLValue().(VariableAccess).getTarget()=vsrc_135
		and target_62.getRValue() instanceof Literal
		and target_102.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_62.getLValue().(VariableAccess).getLocation())
}

predicate func_63(Variable vsrc_135, Variable vpix_200, ExprStmt target_107, ExprStmt target_108, PointerDereferenceExpr target_63) {
		target_63.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_63.getParent().(AssignExpr).getRValue() = target_63
		and target_63.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_63.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_63.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_107.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_63.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_108.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_64(Variable vsrc_135, Variable vpix16_137, ExprStmt target_33, ExprStmt target_111, VariableAccess target_64) {
		target_64.getTarget()=vpix16_137
		and target_64.getParent().(AssignExpr).getLValue() = target_64
		and target_64.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_64.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
		and target_33.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_64.getLocation())
		and target_64.getLocation().isBefore(target_111.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

/*predicate func_65(Variable vsrc_135, PointerFieldAccess target_65) {
		target_65.getTarget().getName()="l"
		and target_65.getQualifier().(VariableAccess).getTarget()=vsrc_135
}

*/
predicate func_66(Variable vsrc_135, ExprStmt target_107, ExprStmt target_108, AssignPointerAddExpr target_66) {
		target_66.getLValue().(VariableAccess).getTarget()=vsrc_135
		and target_66.getRValue() instanceof Literal
		and target_107.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_66.getLValue().(VariableAccess).getLocation())
}

predicate func_67(Variable vsrc_135, Variable vpix_200, ExprStmt target_116, ExprStmt target_117, PointerDereferenceExpr target_67) {
		target_67.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_67.getParent().(AssignExpr).getRValue() = target_67
		and target_67.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_67.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_116.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_67.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_67.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_117.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_68(Variable vsrc_135, Variable vpix_200, ExprStmt target_108, ExprStmt target_69, PointerDereferenceExpr target_68) {
		target_68.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_68.getParent().(AssignExpr).getRValue() = target_68
		and target_68.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_68.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_68.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_69.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_69(Variable vsrc_135, Variable vpix_200, VariableAccess target_118, ExprStmt target_69) {
		target_69.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_69.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_69.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_69.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_118
}

/*predicate func_70(Variable vsrc_135, Variable vpix_200, ExprStmt target_117, ExprStmt target_71, ExprStmt target_119, PointerDereferenceExpr target_70) {
		target_70.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_135
		and target_70.getParent().(AssignExpr).getRValue() = target_70
		and target_70.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_70.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_70.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_71.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_70.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_119.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

*/
predicate func_71(Variable vsrc_135, Variable vpix32_138, VariableAccess target_118, ExprStmt target_71) {
		target_71.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix32_138
		and target_71.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_71.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
		and target_71.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_118
}

/*predicate func_72(Variable vsrc_135, Variable vpix32_138, ExprStmt target_69, ExprStmt target_74, ExprStmt target_35, ExprStmt target_120, VariableAccess target_72) {
		target_72.getTarget()=vpix32_138
		and target_72.getParent().(AssignExpr).getLValue() = target_72
		and target_72.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_72.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
		and target_69.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_72.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_72.getParent().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_74.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_35.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_72.getLocation())
		and target_72.getLocation().isBefore(target_120.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

*/
/*predicate func_73(Variable vsrc_135, ExprStmt target_69, ExprStmt target_74, PointerFieldAccess target_73) {
		target_73.getTarget().getName()="l"
		and target_73.getQualifier().(VariableAccess).getTarget()=vsrc_135
		and target_69.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_73.getQualifier().(VariableAccess).getLocation())
		and target_73.getQualifier().(VariableAccess).getLocation().isBefore(target_74.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_74(Variable vsrc_135, VariableAccess target_118, ExprStmt target_71, ExprStmt target_74) {
		target_74.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vsrc_135
		and target_74.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and target_74.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_118
		and target_71.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_74.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_75(Parameter vavctx_131, ExprStmt target_75) {
		target_75.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_75.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_131
		and target_75.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_75.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
}

predicate func_76(Parameter vavctx_131, ExprStmt target_76) {
		target_76.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_131
		and target_76.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_76.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Skip beyond picture bounds\n"
}

predicate func_77(Variable vp1_136, EqualityOperation target_77) {
		target_77.getAnOperand().(VariableAccess).getTarget()=vp1_136
		and target_77.getAnOperand().(Literal).getValue()="0"
}

predicate func_78(Variable voutput_134, ExprStmt target_78) {
		target_78.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutput_134
		and target_78.getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
}

predicate func_79(Parameter vpic_131, Parameter vdepth_131, Variable voutput_134, Variable voutput_end_134, Variable vp1_136, LogicalOrExpr target_79) {
		target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpic_131
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_134
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vp1_136
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdepth_131
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voutput_end_134
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpic_131
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_134
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vp1_136
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdepth_131
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_79.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voutput_end_134
}

predicate func_80(Variable vp2_136, Variable vi_136, RelationalOperation target_80) {
		 (target_80 instanceof GTExpr or target_80 instanceof LTExpr)
		and target_80.getLesserOperand().(VariableAccess).getTarget()=vi_136
		and target_80.getGreaterOperand().(VariableAccess).getTarget()=vp2_136
}

predicate func_81(Variable vp2_136, Variable vpos_136, ExprStmt target_81) {
		target_81.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vpos_136
		and target_81.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vp2_136
}

predicate func_82(Variable vi_136, PostfixIncrExpr target_82) {
		target_82.getOperand().(VariableAccess).getTarget()=vi_136
}

predicate func_83(Variable voutput_134, ExprStmt target_83) {
		target_83.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=voutput_134
		and target_83.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_84(Parameter vavctx_131, BlockStmt target_84) {
		target_84.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_84.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_131
		and target_84.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_84.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_84.getStmt(1).(ReturnStmt).getExpr() instanceof UnaryMinusExpr
}

predicate func_86(Variable vsrc_135, RelationalOperation target_86) {
		 (target_86 instanceof GTExpr or target_86 instanceof LTExpr)
		and target_86.getLesserOperand().(VariableAccess).getTarget()=vsrc_135
		and target_86.getGreaterOperand() instanceof PointerArithmeticOperation
}

predicate func_89(Variable vp2_136, EqualityOperation target_89) {
		target_89.getAnOperand().(VariableAccess).getTarget()=vp2_136
		and target_89.getAnOperand().(Literal).getValue()="0"
}

predicate func_91(Variable vp1_136, Variable vpos_136, ExprStmt target_91) {
		target_91.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vpos_136
		and target_91.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vp1_136
}

predicate func_94(Variable vp2_136, EqualityOperation target_94) {
		target_94.getAnOperand().(VariableAccess).getTarget()=vp2_136
		and target_94.getAnOperand().(Literal).getValue()="2"
}

predicate func_95(Variable vp2_136, Variable vline_136, ExprStmt target_95) {
		target_95.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vline_136
		and target_95.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vp2_136
}

predicate func_96(Parameter vpic_131, Parameter vdepth_131, Variable voutput_134, Variable voutput_end_134, Variable vp2_136, LogicalOrExpr target_96) {
		target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpic_131
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_134
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vp2_136
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdepth_131
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voutput_end_134
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpic_131
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutput_134
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vp2_136
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdepth_131
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_96.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voutput_end_134
}

predicate func_99(Variable vsrc_135, Variable vpix16_137, ExprStmt target_99) {
		target_99.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix16_137
		and target_99.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_99.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
}

predicate func_102(Variable vsrc_135, Variable vpix32_138, ExprStmt target_102) {
		target_102.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix32_138
		and target_102.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_102.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
}

predicate func_107(Variable vsrc_135, Variable vpix16_137, ExprStmt target_107) {
		target_107.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpix16_137
		and target_107.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_107.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_135
}

predicate func_108(Variable vpix_200, ExprStmt target_108) {
		target_108.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_108.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_108.getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
}

predicate func_111(Variable voutput_134, Variable vpix16_137, ExprStmt target_111) {
		target_111.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voutput_134
		and target_111.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpix16_137
}

predicate func_116(Variable vpix_200, ExprStmt target_116) {
		target_116.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_116.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_116.getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
}

predicate func_117(Variable vpix_200, ExprStmt target_117) {
		target_117.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_117.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_117.getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
}

predicate func_118(Parameter vdepth_131, VariableAccess target_118) {
		target_118.getTarget()=vdepth_131
}

predicate func_119(Variable voutput_134, Variable vpix_200, ExprStmt target_119) {
		target_119.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutput_134
		and target_119.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpix_200
		and target_119.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_120(Variable voutput_134, Variable vpix32_138, ExprStmt target_120) {
		target_120.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voutput_134
		and target_120.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpix32_138
}

from Function func, Parameter vavctx_131, Parameter vpic_131, Parameter vdepth_131, Parameter vdata_132, Parameter vsrcsize_132, Variable voutput_134, Variable voutput_end_134, Variable vsrc_135, Variable vp1_136, Variable vp2_136, Variable vline_136, Variable vpos_136, Variable vi_136, Variable vpix16_137, Variable vpix32_138, Variable vpix_200, StringLiteral target_0, VariableAccess target_1, Literal target_2, Literal target_3, Literal target_4, UnaryMinusExpr target_31, EqualityOperation target_32, ExprStmt target_33, EqualityOperation target_34, ExprStmt target_35, RelationalOperation target_36, MulExpr target_37, DeclStmt target_38, IfStmt target_39, ExprStmt target_40, ForStmt target_41, VariableAccess target_43, VariableAccess target_44, DeclStmt target_47, VariableAccess target_48, PointerDereferenceExpr target_50, PointerDereferenceExpr target_51, LogicalAndExpr target_52, PointerDereferenceExpr target_54, PointerDereferenceExpr target_55, AssignPointerAddExpr target_56, PointerDereferenceExpr target_57, PostfixIncrExpr target_58, PointerFieldAccess target_59, AssignPointerAddExpr target_60, PointerFieldAccess target_61, AssignPointerAddExpr target_62, PointerDereferenceExpr target_63, VariableAccess target_64, AssignPointerAddExpr target_66, PointerDereferenceExpr target_67, PointerDereferenceExpr target_68, ExprStmt target_69, ExprStmt target_71, ExprStmt target_74, ExprStmt target_75, ExprStmt target_76, EqualityOperation target_77, ExprStmt target_78, LogicalOrExpr target_79, RelationalOperation target_80, ExprStmt target_81, PostfixIncrExpr target_82, ExprStmt target_83, BlockStmt target_84, RelationalOperation target_86, EqualityOperation target_89, ExprStmt target_91, EqualityOperation target_94, ExprStmt target_95, LogicalOrExpr target_96, ExprStmt target_99, ExprStmt target_102, ExprStmt target_107, ExprStmt target_108, ExprStmt target_111, ExprStmt target_116, ExprStmt target_117, VariableAccess target_118, ExprStmt target_119, ExprStmt target_120
where
func_0(func, target_0)
and func_1(vsrcsize_132, target_52, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and not func_5(func)
and not func_6(vp1_136)
and not func_7(vp2_136)
and not func_8(vavctx_131, target_52, target_75, target_76)
and not func_13(vp1_136)
and not func_14(vp2_136)
and not func_15(func)
and not func_16(vsrc_135)
and not func_17(target_32, func)
and not func_18(voutput_134)
and not func_19(func)
and not func_20(voutput_134, vsrc_135, target_78, target_33)
and not func_21(vpix16_137)
and not func_22(voutput_134, vp2_136, vi_136, target_32, target_35, target_79, target_80, target_81, target_82)
and not func_25(vpix_200)
and not func_26(vpix16_137)
and not func_27(vpix_200)
and not func_28(vpix_200)
and not func_29(vpix_200)
and not func_30(vpix32_138)
and func_31(func, target_31)
and func_32(vdepth_131, target_32)
and func_33(voutput_134, vpix16_137, target_33)
and func_34(vdepth_131, target_34)
and func_35(voutput_134, vpix32_138, target_35)
and func_36(vline_136, target_84, target_36)
and func_37(vdepth_131, vp2_136, target_37)
and func_38(target_77, func, target_38)
and func_39(vpic_131, voutput_134, voutput_end_134, vp1_136, target_77, target_39)
and func_40(vp1_136, vpos_136, target_77, target_40)
and func_41(vdepth_131, vp1_136, vi_136, target_77, target_41)
and func_43(vsrc_135, vpix16_137, target_43)
and func_44(vsrc_135, vpix32_138, target_44)
and func_47(func, target_47)
and func_48(vdata_132, vsrcsize_132, vsrc_135, target_52, target_48)
and func_50(vsrc_135, vp1_136, target_86, target_77, target_50)
and func_51(vsrc_135, vp2_136, target_52, target_89, target_51)
and func_52(vdata_132, vsrcsize_132, vsrc_135, target_84, target_52)
and func_54(vsrc_135, vp1_136, target_52, target_77, target_91, target_54)
and func_55(vsrc_135, vp2_136, target_94, target_95, target_55)
and func_56(vsrc_135, target_56)
and func_57(voutput_134, vsrc_135, target_96, target_57)
and func_58(vsrc_135, target_78, target_99, target_58)
and func_59(vsrc_135, target_59)
and func_60(vsrc_135, target_99, target_102, target_60)
and func_61(vsrc_135, target_61)
and func_62(vsrc_135, target_102, target_62)
and func_63(vsrc_135, vpix_200, target_107, target_108, target_63)
and func_64(vsrc_135, vpix16_137, target_33, target_111, target_64)
and func_66(vsrc_135, target_107, target_108, target_66)
and func_67(vsrc_135, vpix_200, target_116, target_117, target_67)
and func_68(vsrc_135, vpix_200, target_108, target_69, target_68)
and func_69(vsrc_135, vpix_200, target_118, target_69)
and func_71(vsrc_135, vpix32_138, target_118, target_71)
and func_74(vsrc_135, target_118, target_71, target_74)
and func_75(vavctx_131, target_75)
and func_76(vavctx_131, target_76)
and func_77(vp1_136, target_77)
and func_78(voutput_134, target_78)
and func_79(vpic_131, vdepth_131, voutput_134, voutput_end_134, vp1_136, target_79)
and func_80(vp2_136, vi_136, target_80)
and func_81(vp2_136, vpos_136, target_81)
and func_82(vi_136, target_82)
and func_83(voutput_134, target_83)
and func_84(vavctx_131, target_84)
and func_86(vsrc_135, target_86)
and func_89(vp2_136, target_89)
and func_91(vp1_136, vpos_136, target_91)
and func_94(vp2_136, target_94)
and func_95(vp2_136, vline_136, target_95)
and func_96(vpic_131, vdepth_131, voutput_134, voutput_end_134, vp2_136, target_96)
and func_99(vsrc_135, vpix16_137, target_99)
and func_102(vsrc_135, vpix32_138, target_102)
and func_107(vsrc_135, vpix16_137, target_107)
and func_108(vpix_200, target_108)
and func_111(voutput_134, vpix16_137, target_111)
and func_116(vpix_200, target_116)
and func_117(vpix_200, target_117)
and func_118(vdepth_131, target_118)
and func_119(voutput_134, vpix_200, target_119)
and func_120(voutput_134, vpix32_138, target_120)
and vavctx_131.getType().hasName("AVCodecContext *")
and vpic_131.getType().hasName("AVPicture *")
and vdepth_131.getType().hasName("int")
and vdata_132.getType().hasName("const uint8_t *")
and vsrcsize_132.getType().hasName("int")
and voutput_134.getType().hasName("uint8_t *")
and voutput_end_134.getType().hasName("uint8_t *")
and vsrc_135.getType().hasName("const uint8_t *")
and vp1_136.getType().hasName("int")
and vp2_136.getType().hasName("int")
and vline_136.getType().hasName("int")
and vpos_136.getType().hasName("int")
and vi_136.getType().hasName("int")
and vpix16_137.getType().hasName("uint16_t")
and vpix32_138.getType().hasName("uint32_t")
and vpix_200.getType().hasName("uint8_t[3]")
and vavctx_131.getFunction() = func
and vpic_131.getFunction() = func
and vdepth_131.getFunction() = func
and vdata_132.getFunction() = func
and vsrcsize_132.getFunction() = func
and voutput_134.(LocalVariable).getFunction() = func
and voutput_end_134.(LocalVariable).getFunction() = func
and vsrc_135.(LocalVariable).getFunction() = func
and vp1_136.(LocalVariable).getFunction() = func
and vp2_136.(LocalVariable).getFunction() = func
and vline_136.(LocalVariable).getFunction() = func
and vpos_136.(LocalVariable).getFunction() = func
and vi_136.(LocalVariable).getFunction() = func
and vpix16_137.(LocalVariable).getFunction() = func
and vpix32_138.(LocalVariable).getFunction() = func
and vpix_200.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
