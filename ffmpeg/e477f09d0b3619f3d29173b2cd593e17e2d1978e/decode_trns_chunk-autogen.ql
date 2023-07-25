/**
 * @name ffmpeg-e477f09d0b3619f3d29173b2cd593e17e2d1978e-decode_trns_chunk
 * @id cpp/ffmpeg/e477f09d0b3619f3d29173b2cd593e17e2d1978e/decode-trns-chunk
 * @description ffmpeg-e477f09d0b3619f3d29173b2cd593e17e2d1978e-libavcodec/pngdec.c-decode_trns_chunk CVE-2017-7863
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_770, BlockStmt target_9, EqualityOperation target_6) {
	exists(NotExpr target_0 |
		target_0.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_0.getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_9
		and target_0.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_770, LogicalOrExpr target_10) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_770
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="trns before IHDR\n"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10)
}

predicate func_2(LogicalOrExpr target_10, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vavctx_770, Parameter vs_770, ExprStmt target_11, AddressOfExpr target_12, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_3.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_770
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="trns after IDAT\n"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_3)
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vs_770, Parameter vlength_771, Variable vv_773, Variable vi_773, ExprStmt target_13, LogicalOrExpr target_8, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof EqualityOperation
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_771
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_4.getThen().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_773
		and target_4.getThen().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_773
		and target_4.getThen().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_771
		and target_4.getThen().(BlockStmt).getStmt(1).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_773
		and target_4.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vv_773
		and target_4.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_byte")
		and target_4.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_4.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_4.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_4.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_4.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_4.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ForStmt
		and target_4.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_4)
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_5(Parameter vs_770, ReturnStmt target_14, LogicalOrExpr target_10, LogicalOrExpr target_8) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand() instanceof LogicalOrExpr
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getThen()=target_14
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_6(Parameter vs_770, BlockStmt target_9, EqualityOperation target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_6.getAnOperand().(BitwiseOrExpr).getValue()="3"
		and target_6.getParent().(IfStmt).getThen()=target_9
}

predicate func_7(Parameter vs_770, Parameter vlength_771, Variable vv_773, Variable vi_773, LogicalOrExpr target_10, ForStmt target_7) {
		target_7.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_773
		and target_7.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_773
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_771
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_7.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_773
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vv_773
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_mod_uintp2_c")
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("bytestream2_get_be16")
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_bswap16")
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_773
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="transparent_color_be"
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_773
		and target_7.getStmt().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vv_773
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_8(Parameter vs_770, Parameter vlength_771, ReturnStmt target_14, LogicalOrExpr target_8) {
		target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlength_771
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlength_771
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="6"
		and target_8.getParent().(IfStmt).getThen()=target_14
}

predicate func_9(Parameter vs_770, Parameter vlength_771, BlockStmt target_9) {
		target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_771
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_9.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_10(Parameter vs_770, LogicalOrExpr target_10) {
		target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_11(Parameter vs_770, Variable vv_773, Variable vi_773, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="transparent_color_be"
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_773
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vv_773
}

predicate func_12(Parameter vs_770, AddressOfExpr target_12) {
		target_12.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
}

predicate func_13(Parameter vs_770, Variable vv_773, Variable vi_773, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="palette"
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_773
		and target_13.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="palette"
		and target_13.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_770
		and target_13.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_773
		and target_13.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="16777215"
		and target_13.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vv_773
		and target_13.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_14(ReturnStmt target_14) {
		target_14.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

from Function func, Parameter vavctx_770, Parameter vs_770, Parameter vlength_771, Variable vv_773, Variable vi_773, EqualityOperation target_6, ForStmt target_7, LogicalOrExpr target_8, BlockStmt target_9, LogicalOrExpr target_10, ExprStmt target_11, AddressOfExpr target_12, ExprStmt target_13, ReturnStmt target_14
where
not func_0(vs_770, target_9, target_6)
and not func_1(vavctx_770, target_10)
and not func_2(target_10, func)
and not func_3(vavctx_770, vs_770, target_11, target_12, func)
and not func_4(vs_770, vlength_771, vv_773, vi_773, target_13, target_8, func)
and func_6(vs_770, target_9, target_6)
and func_7(vs_770, vlength_771, vv_773, vi_773, target_10, target_7)
and func_8(vs_770, vlength_771, target_14, target_8)
and func_9(vs_770, vlength_771, target_9)
and func_10(vs_770, target_10)
and func_11(vs_770, vv_773, vi_773, target_11)
and func_12(vs_770, target_12)
and func_13(vs_770, vv_773, vi_773, target_13)
and func_14(target_14)
and vavctx_770.getType().hasName("AVCodecContext *")
and vs_770.getType().hasName("PNGDecContext *")
and vlength_771.getType().hasName("uint32_t")
and vv_773.getType().hasName("int")
and vi_773.getType().hasName("int")
and vavctx_770.getParentScope+() = func
and vs_770.getParentScope+() = func
and vlength_771.getParentScope+() = func
and vv_773.getParentScope+() = func
and vi_773.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
