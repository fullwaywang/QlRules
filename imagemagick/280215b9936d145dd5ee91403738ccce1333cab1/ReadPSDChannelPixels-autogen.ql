/**
 * @name imagemagick-280215b9936d145dd5ee91403738ccce1333cab1-ReadPSDChannelPixels
 * @id cpp/imagemagick/280215b9936d145dd5ee91403738ccce1333cab1/ReadPSDChannelPixels
 * @description imagemagick-280215b9936d145dd5ee91403738ccce1333cab1-coders/psd.c-ReadPSDChannelPixels CVE-2016-7514
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_767, Variable vpixel_772, Variable vq_778, FunctionCall target_0) {
		target_0.getTarget().hasName("SetPixelAlpha")
		and not target_0.getTarget().hasName("SetPSDPixel")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_0.getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_0.getArgument(2).(VariableAccess).getTarget()=vq_778
}

predicate func_1(Parameter vimage_767, Variable vpixel_772, Variable vq_778, FunctionCall target_1) {
		target_1.getTarget().hasName("SetPixelRed")
		and not target_1.getTarget().hasName("SetPSDPixel")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_1.getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_1.getArgument(2).(VariableAccess).getTarget()=vq_778
}

predicate func_4(Parameter vimage_767, ExprStmt target_32, ExprStmt target_35) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="columns"
		and target_4.getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_32.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getQualifier().(VariableAccess).getLocation())
		and target_4.getQualifier().(VariableAccess).getLocation().isBefore(target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Parameter vimage_767, BlockStmt target_61, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="depth"
		and target_5.getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_5.getParent().(EQExpr).getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_61
}

predicate func_6(EqualityOperation target_62, Function func, DeclStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vimage_767, Variable vx_781, Variable vnumber_bits_828, EqualityOperation target_62, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnumber_bits_828
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vx_781
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
}

predicate func_8(Variable vnumber_bits_828, EqualityOperation target_62, IfStmt target_8) {
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnumber_bits_828
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnumber_bits_828
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="8"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
}

predicate func_9(Variable vpixel_772, Variable vbit_827, ConditionalExpr target_9) {
		target_9.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vpixel_772
		and target_9.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(HexLiteral).getValue()="1"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="7"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbit_827
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(Literal).getValue()="0"
		and target_9.getElse().(Literal).getValue()="255"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Parameter vimage_767, Variable vq_778, ExprStmt target_10) {
		target_10.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vq_778
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getTarget().hasName("GetPixelChannels")
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
}

predicate func_11(Variable vx_781, ExprStmt target_11) {
		target_11.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vx_781
}

predicate func_12(Variable vx_781, EqualityOperation target_62, ExprStmt target_12) {
		target_12.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vx_781
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
}

predicate func_13(Parameter vimage_767, Variable vq_778, ExprStmt target_13) {
		target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vq_778
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getTarget().hasName("GetPixelChannels")
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
}

predicate func_14(Parameter vimage_767, VariableAccess target_14) {
		target_14.getTarget()=vimage_767
}

predicate func_16(Variable vq_778, VariableAccess target_16) {
		target_16.getTarget()=vq_778
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_17(EqualityOperation target_62, Function func, ContinueStmt target_17) {
		target_17.toString() = "continue;"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
		and target_17.getEnclosingFunction() = func
}

predicate func_18(Parameter vtype_768, VariableAccess target_18) {
		target_18.getTarget()=vtype_768
}

predicate func_19(Parameter vchannels_768, VariableAccess target_19) {
		target_19.getTarget()=vchannels_768
}

predicate func_20(Parameter vtype_768, VariableAccess target_20) {
		target_20.getTarget()=vtype_768
}

predicate func_21(Variable vpacket_size_784, ExprStmt target_35, VariableAccess target_21) {
		target_21.getTarget()=vpacket_size_784
		and target_21.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_21.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_35
}

predicate func_22(Parameter vexception_769, VariableAccess target_22) {
		target_22.getTarget()=vexception_769
		and target_22.getParent().(FunctionCall).getParent().(PointerAddExpr).getAnOperand() instanceof FunctionCall
}

predicate func_23(Parameter vexception_769, VariableAccess target_23) {
		target_23.getTarget()=vexception_769
		and target_23.getParent().(FunctionCall).getParent().(PointerAddExpr).getAnOperand() instanceof FunctionCall
}

predicate func_24(Parameter vchannels_768, VariableAccess target_24) {
		target_24.getTarget()=vchannels_768
}

predicate func_25(Function func, LabelStmt target_25) {
		target_25.toString() = "label ...:"
		and target_25.getEnclosingFunction() = func
}

predicate func_26(Parameter vimage_767, Parameter vchannels_768, Parameter vtype_768, Variable vpixel_772, Variable vq_778, SwitchStmt target_26) {
		target_26.getExpr().(VariableAccess).getTarget()=vtype_768
		and target_26.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_26.getStmt().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_26.getStmt().(BlockStmt).getStmt(1).(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_26.getStmt().(BlockStmt).getStmt(2).(SwitchCase).getExpr().(UnaryMinusExpr).getValue()="-2"
		and target_26.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="0"
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchannels_768
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_768
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelGray")
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelViaPixelInfo")
		and target_26.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(3).(BreakStmt).toString() = "break;"
		and target_26.getStmt().(BlockStmt).getStmt(5).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelGreen")
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_26.getStmt().(BlockStmt).getStmt(6).(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_26.getStmt().(BlockStmt).getStmt(7).(SwitchCase).getExpr().(Literal).getValue()="2"
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelBlue")
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_26.getStmt().(BlockStmt).getStmt(8).(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_26.getStmt().(BlockStmt).getStmt(9).(SwitchCase).getExpr().(Literal).getValue()="3"
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelBlack")
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha_trait"
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_26.getStmt().(BlockStmt).getStmt(10).(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_26.getStmt().(BlockStmt).getStmt(11).(SwitchCase).getExpr().(Literal).getValue()="4"
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IssRGBCompatibleColorspace")
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vchannels_768
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="3"
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha_trait"
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_26.getStmt().(BlockStmt).getStmt(12).(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_26.getStmt().(BlockStmt).getStmt(13).(SwitchCase).toString() = "default: "
		and target_26.getStmt().(BlockStmt).getStmt(14).(BreakStmt).toString() = "break;"
}

/*predicate func_27(Function func, SwitchCase target_27) {
		target_27.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_27.getEnclosingFunction() = func
}

*/
/*predicate func_28(Function func, BreakStmt target_28) {
		target_28.toString() = "break;"
		and target_28.getEnclosingFunction() = func
}

*/
/*predicate func_29(Function func, SwitchCase target_29) {
		target_29.getExpr().(UnaryMinusExpr).getValue()="-2"
		and target_29.getEnclosingFunction() = func
}

*/
/*predicate func_30(Function func, SwitchCase target_30) {
		target_30.getExpr().(Literal).getValue()="0"
		and target_30.getEnclosingFunction() = func
}

*/
/*predicate func_31(Parameter vchannels_768, Parameter vtype_768, ExprStmt target_32, LogicalOrExpr target_31) {
		target_31.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchannels_768
		and target_31.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_31.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_768
		and target_31.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-2"
		and target_31.getParent().(IfStmt).getThen()=target_32
}

*/
predicate func_32(Parameter vimage_767, Variable vpixel_772, Variable vq_778, ExprStmt target_32) {
		target_32.getExpr().(FunctionCall).getTarget().hasName("SetPixelGray")
		and target_32.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_32.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

/*predicate func_33(Parameter vimage_767, Parameter vexception_769, Variable vpixel_772, Variable vq_778, Variable vpacket_size_784, Variable vbit_827, Variable vnumber_bits_828, IfStmt target_33) {
		target_33.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
		and target_33.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_size_784
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelIndex")
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ScaleQuantumToChar")
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_772
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelIndex")
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ScaleQuantumToShort")
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_772
		and target_33.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelViaPixelInfo")
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("ConstrainColormapIndex")
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("GetPixelIndex")
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexception_769
		and target_33.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbit_827
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnumber_bits_828
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbit_827
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_33.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(5) instanceof ContinueStmt
}

*/
/*predicate func_34(Variable vpacket_size_784, EqualityOperation target_34) {
		target_34.getAnOperand().(VariableAccess).getTarget()=vpacket_size_784
		and target_34.getAnOperand().(Literal).getValue()="1"
}

*/
predicate func_35(Parameter vimage_767, Variable vpixel_772, Variable vq_778, ExprStmt target_35) {
		target_35.getExpr().(FunctionCall).getTarget().hasName("SetPixelIndex")
		and target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_35.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ScaleQuantumToChar")
		and target_35.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_772
		and target_35.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

/*predicate func_36(Parameter vimage_767, Variable vpixel_772, Variable vq_778, ExprStmt target_36) {
		target_36.getExpr().(FunctionCall).getTarget().hasName("SetPixelIndex")
		and target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_36.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ScaleQuantumToShort")
		and target_36.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_772
		and target_36.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_37(Parameter vimage_767, Parameter vexception_769, Variable vq_778, ExprStmt target_37) {
		target_37.getExpr().(FunctionCall).getTarget().hasName("SetPixelViaPixelInfo")
		and target_37.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("ConstrainColormapIndex")
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("GetPixelIndex")
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_778
		and target_37.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexception_769
		and target_37.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_38(Parameter vimage_767, Variable vq_778, Variable vbit_827, Variable vnumber_bits_828, IfStmt target_38) {
		target_38.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_38.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_38.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_38.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_38.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbit_827
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbit_827
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnumber_bits_828
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbit_827
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelIndex")
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof ConditionalExpr
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelViaPixelInfo")
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_38.getThen().(BlockStmt).getStmt(3).(ForStmt).getStmt().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_38.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_38.getThen().(BlockStmt).getStmt(5) instanceof ContinueStmt
}

*/
/*predicate func_39(Parameter vimage_767, Variable vq_778, ExprStmt target_39) {
		target_39.getExpr().(FunctionCall).getTarget().hasName("SetPixelIndex")
		and target_39.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_39.getExpr().(FunctionCall).getArgument(1) instanceof ConditionalExpr
		and target_39.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_40(Parameter vimage_767, Parameter vexception_769, Variable vq_778, ExprStmt target_40) {
		target_40.getExpr().(FunctionCall).getTarget().hasName("SetPixelViaPixelInfo")
		and target_40.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("ConstrainColormapIndex")
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("GetPixelIndex")
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_778
		and target_40.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexception_769
		and target_40.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_41(Function func, BreakStmt target_41) {
		target_41.toString() = "break;"
		and target_41.getEnclosingFunction() = func
}

*/
/*predicate func_42(Function func, SwitchCase target_42) {
		target_42.getExpr().(Literal).getValue()="1"
		and target_42.getEnclosingFunction() = func
}

*/
/*predicate func_43(Parameter vimage_767, Variable vpixel_772, Variable vq_778, IfStmt target_43) {
		target_43.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
		and target_43.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_43.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_43.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_43.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_43.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_43.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelGreen")
		and target_43.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_43.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_43.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_44(Function func, BreakStmt target_44) {
		target_44.toString() = "break;"
		and target_44.getEnclosingFunction() = func
}

*/
/*predicate func_45(Function func, SwitchCase target_45) {
		target_45.getExpr().(Literal).getValue()="2"
		and target_45.getEnclosingFunction() = func
}

*/
/*predicate func_46(Parameter vimage_767, Variable vpixel_772, Variable vq_778, IfStmt target_46) {
		target_46.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
		and target_46.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_46.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelBlue")
		and target_46.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_46.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_46.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_47(Function func, BreakStmt target_47) {
		target_47.toString() = "break;"
		and target_47.getEnclosingFunction() = func
}

*/
/*predicate func_48(Function func, SwitchCase target_48) {
		target_48.getExpr().(Literal).getValue()="3"
		and target_48.getEnclosingFunction() = func
}

*/
/*predicate func_49(Parameter vimage_767, Variable vpixel_772, Variable vq_778, IfStmt target_49) {
		target_49.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_49.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_49.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelBlack")
		and target_49.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_49.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_49.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
		and target_49.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha_trait"
		and target_49.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_49.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_49.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_49.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_49.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_50(Parameter vimage_767, PointerFieldAccess target_50) {
		target_50.getTarget().getName()="alpha_trait"
		and target_50.getQualifier().(VariableAccess).getTarget()=vimage_767
}

*/
/*predicate func_52(Function func, BreakStmt target_52) {
		target_52.toString() = "break;"
		and target_52.getEnclosingFunction() = func
}

*/
/*predicate func_53(Function func, SwitchCase target_53) {
		target_53.getExpr().(Literal).getValue()="4"
		and target_53.getEnclosingFunction() = func
}

*/
/*predicate func_54(Parameter vimage_767, Parameter vchannels_768, IfStmt target_54) {
		target_54.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IssRGBCompatibleColorspace")
		and target_54.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_54.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_54.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vchannels_768
		and target_54.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="3"
		and target_54.getThen().(BreakStmt).toString() = "break;"
}

*/
/*predicate func_56(Parameter vimage_767, Variable vpixel_772, Variable vq_778, IfStmt target_56) {
		target_56.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="alpha_trait"
		and target_56.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_56.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetPixelAlpha")
		and target_56.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_56.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpixel_772
		and target_56.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_778
}

*/
/*predicate func_57(Function func, BreakStmt target_57) {
		target_57.toString() = "break;"
		and target_57.getEnclosingFunction() = func
}

*/
/*predicate func_58(Function func, SwitchCase target_58) {
		target_58.toString() = "default: "
		and target_58.getEnclosingFunction() = func
}

*/
/*predicate func_59(Function func, BreakStmt target_59) {
		target_59.toString() = "break;"
		and target_59.getEnclosingFunction() = func
}

*/
predicate func_60(Function func, LabelStmt target_60) {
		target_60.toString() = "label ...:"
		and target_60.getEnclosingFunction() = func
}

predicate func_61(Variable vbit_827, Variable vnumber_bits_828, BlockStmt target_61) {
		target_61.getStmt(1) instanceof ExprStmt
		and target_61.getStmt(2) instanceof IfStmt
		and target_61.getStmt(3).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbit_827
		and target_61.getStmt(3).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_61.getStmt(3).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbit_827
		and target_61.getStmt(3).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnumber_bits_828
		and target_61.getStmt(3).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbit_827
		and target_61.getStmt(3).(ForStmt).getStmt() instanceof BlockStmt
}

predicate func_62(Parameter vimage_767, EqualityOperation target_62) {
		target_62.getAnOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_62.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_62.getAnOperand() instanceof Literal
}

from Function func, Parameter vimage_767, Parameter vchannels_768, Parameter vtype_768, Parameter vexception_769, Variable vpixel_772, Variable vq_778, Variable vx_781, Variable vpacket_size_784, Variable vbit_827, Variable vnumber_bits_828, FunctionCall target_0, FunctionCall target_1, PointerFieldAccess target_5, DeclStmt target_6, ExprStmt target_7, IfStmt target_8, ConditionalExpr target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, VariableAccess target_14, VariableAccess target_16, ContinueStmt target_17, VariableAccess target_18, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, VariableAccess target_22, VariableAccess target_23, VariableAccess target_24, LabelStmt target_25, SwitchStmt target_26, ExprStmt target_32, ExprStmt target_35, LabelStmt target_60, BlockStmt target_61, EqualityOperation target_62
where
func_0(vimage_767, vpixel_772, vq_778, target_0)
and func_1(vimage_767, vpixel_772, vq_778, target_1)
and not func_4(vimage_767, target_32, target_35)
and func_5(vimage_767, target_61, target_5)
and func_6(target_62, func, target_6)
and func_7(vimage_767, vx_781, vnumber_bits_828, target_62, target_7)
and func_8(vnumber_bits_828, target_62, target_8)
and func_9(vpixel_772, vbit_827, target_9)
and func_10(vimage_767, vq_778, target_10)
and func_11(vx_781, target_11)
and func_12(vx_781, target_62, target_12)
and func_13(vimage_767, vq_778, target_13)
and func_14(vimage_767, target_14)
and func_16(vq_778, target_16)
and func_17(target_62, func, target_17)
and func_18(vtype_768, target_18)
and func_19(vchannels_768, target_19)
and func_20(vtype_768, target_20)
and func_21(vpacket_size_784, target_35, target_21)
and func_22(vexception_769, target_22)
and func_23(vexception_769, target_23)
and func_24(vchannels_768, target_24)
and func_25(func, target_25)
and func_26(vimage_767, vchannels_768, vtype_768, vpixel_772, vq_778, target_26)
and func_32(vimage_767, vpixel_772, vq_778, target_32)
and func_35(vimage_767, vpixel_772, vq_778, target_35)
and func_60(func, target_60)
and func_61(vbit_827, vnumber_bits_828, target_61)
and func_62(vimage_767, target_62)
and vimage_767.getType().hasName("Image *")
and vchannels_768.getType().hasName("const size_t")
and vtype_768.getType().hasName("const ssize_t")
and vexception_769.getType().hasName("ExceptionInfo *")
and vpixel_772.getType().hasName("Quantum")
and vq_778.getType().hasName("Quantum *")
and vx_781.getType().hasName("ssize_t")
and vpacket_size_784.getType().hasName("size_t")
and vbit_827.getType().hasName("ssize_t")
and vnumber_bits_828.getType().hasName("ssize_t")
and vimage_767.getParentScope+() = func
and vchannels_768.getParentScope+() = func
and vtype_768.getParentScope+() = func
and vexception_769.getParentScope+() = func
and vpixel_772.getParentScope+() = func
and vq_778.getParentScope+() = func
and vx_781.getParentScope+() = func
and vpacket_size_784.getParentScope+() = func
and vbit_827.getParentScope+() = func
and vnumber_bits_828.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
