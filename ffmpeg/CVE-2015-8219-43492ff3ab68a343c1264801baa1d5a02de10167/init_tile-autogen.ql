/**
 * @name ffmpeg-43492ff3ab68a343c1264801baa1d5a02de10167-init_tile
 * @id cpp/ffmpeg/43492ff3ab68a343c1264801baa1d5a02de10167/init-tile
 * @description ffmpeg-43492ff3ab68a343c1264801baa1d5a02de10167-libavcodec/jpeg2000dec.c-init_tile CVE-2015-8219
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_819) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("av_clip_c")
		and target_0.getArgument(0) instanceof AddExpr
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="image_offset_x"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819)
}

predicate func_1(Parameter vs_819) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("av_clip_c")
		and target_1.getArgument(0) instanceof AddExpr
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="image_offset_x"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819)
}

predicate func_2(Parameter vs_819) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("av_clip_c")
		and target_2.getArgument(0) instanceof AddExpr
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_2.getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819)
}

predicate func_3(Parameter vs_819) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("av_clip_c")
		and target_3.getArgument(0) instanceof AddExpr
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_3.getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819)
}

/*predicate func_4(Variable vtilex_822, Parameter vs_819, AddExpr target_4) {
		target_4.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtilex_822
		and target_4.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_width"
		and target_4.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_x"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_4.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="image_offset_x"
		and target_4.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
/*predicate func_5(Variable vtilex_822, Parameter vs_819, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="image_offset_x"
		and target_5.getQualifier().(VariableAccess).getTarget()=vs_819
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtilex_822
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_width"
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_x"
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
predicate func_6(Parameter vs_819, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="tile_width"
		and target_6.getQualifier().(VariableAccess).getTarget()=vs_819
}

predicate func_7(Parameter vs_819, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="tile_offset_x"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_819
}

predicate func_8(Parameter vs_819, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="image_offset_x"
		and target_8.getQualifier().(VariableAccess).getTarget()=vs_819
}

/*predicate func_9(Variable vtiley_823, Parameter vs_819, AddExpr target_9) {
		target_9.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtiley_823
		and target_9.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_height"
		and target_9.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_9.getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_y"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_9.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_9.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
/*predicate func_10(Variable vtiley_823, Parameter vs_819, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="image_offset_y"
		and target_10.getQualifier().(VariableAccess).getTarget()=vs_819
		and target_10.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtiley_823
		and target_10.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_height"
		and target_10.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_10.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_y"
		and target_10.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
predicate func_11(Parameter vs_819, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="tile_height"
		and target_11.getQualifier().(VariableAccess).getTarget()=vs_819
}

predicate func_12(Parameter vs_819, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="tile_offset_y"
		and target_12.getQualifier().(VariableAccess).getTarget()=vs_819
}

predicate func_13(Parameter vs_819, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="image_offset_y"
		and target_13.getQualifier().(VariableAccess).getTarget()=vs_819
}

/*predicate func_14(Variable vtilex_822, Parameter vs_819, AddExpr target_14) {
		target_14.getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtilex_822
		and target_14.getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_14.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_width"
		and target_14.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_14.getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_x"
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_14.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_14.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
/*predicate func_15(Variable vtilex_822, Parameter vs_819, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="width"
		and target_15.getQualifier().(VariableAccess).getTarget()=vs_819
		and target_15.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtilex_822
		and target_15.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_15.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_width"
		and target_15.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_15.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_x"
		and target_15.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
predicate func_16(Parameter vs_819, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="width"
		and target_16.getQualifier().(VariableAccess).getTarget()=vs_819
}

/*predicate func_17(Variable vtiley_823, Parameter vs_819, AddExpr target_17) {
		target_17.getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtiley_823
		and target_17.getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_17.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_height"
		and target_17.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_17.getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_y"
		and target_17.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_17.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_17.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
/*predicate func_18(Variable vtiley_823, Parameter vs_819, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="height"
		and target_18.getQualifier().(VariableAccess).getTarget()=vs_819
		and target_18.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtiley_823
		and target_18.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_18.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_height"
		and target_18.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_18.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_y"
		and target_18.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
}

*/
predicate func_19(Parameter vs_819, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="height"
		and target_19.getQualifier().(VariableAccess).getTarget()=vs_819
}

predicate func_20(Variable vtilex_822, Parameter vs_819, ConditionalExpr target_20) {
		target_20.getCondition().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="image_offset_x"
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_20.getThen().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtilex_822
		and target_20.getThen().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_width"
		and target_20.getThen().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_20.getThen().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_x"
		and target_20.getThen().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_20.getElse().(PointerFieldAccess).getTarget().getName()="image_offset_x"
		and target_20.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_20.getParent().(AssignExpr).getRValue() = target_20
		and target_20.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coord"
		and target_20.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_21(Variable vtilex_822, Parameter vs_819, ConditionalExpr target_21) {
		target_21.getCondition().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_21.getThen().(PointerFieldAccess).getTarget().getName()="width"
		and target_21.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_21.getElse().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtilex_822
		and target_21.getElse().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_21.getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_width"
		and target_21.getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_21.getElse().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_x"
		and target_21.getElse().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_21.getParent().(AssignExpr).getRValue() = target_21
		and target_21.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coord"
		and target_21.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_21.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_22(Variable vtiley_823, Parameter vs_819, ConditionalExpr target_22) {
		target_22.getCondition().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_22.getThen().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtiley_823
		and target_22.getThen().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_height"
		and target_22.getThen().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_22.getThen().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_y"
		and target_22.getThen().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_22.getElse().(PointerFieldAccess).getTarget().getName()="image_offset_y"
		and target_22.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_22.getParent().(AssignExpr).getRValue() = target_22
		and target_22.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coord"
		and target_22.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_22.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_23(Variable vtiley_823, Parameter vs_819, ConditionalExpr target_23) {
		target_23.getCondition().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_23.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_23.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_23.getThen().(PointerFieldAccess).getTarget().getName()="height"
		and target_23.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_23.getElse().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtiley_823
		and target_23.getElse().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_23.getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tile_height"
		and target_23.getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_23.getElse().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tile_offset_y"
		and target_23.getElse().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_819
		and target_23.getParent().(AssignExpr).getRValue() = target_23
		and target_23.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coord"
		and target_23.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_23.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

from Function func, Variable vtilex_822, Variable vtiley_823, Parameter vs_819, PointerFieldAccess target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, PointerFieldAccess target_11, PointerFieldAccess target_12, PointerFieldAccess target_13, PointerFieldAccess target_16, PointerFieldAccess target_19, ConditionalExpr target_20, ConditionalExpr target_21, ConditionalExpr target_22, ConditionalExpr target_23
where
not func_0(vs_819)
and not func_1(vs_819)
and not func_2(vs_819)
and not func_3(vs_819)
and func_6(vs_819, target_6)
and func_7(vs_819, target_7)
and func_8(vs_819, target_8)
and func_11(vs_819, target_11)
and func_12(vs_819, target_12)
and func_13(vs_819, target_13)
and func_16(vs_819, target_16)
and func_19(vs_819, target_19)
and func_20(vtilex_822, vs_819, target_20)
and func_21(vtilex_822, vs_819, target_21)
and func_22(vtiley_823, vs_819, target_22)
and func_23(vtiley_823, vs_819, target_23)
and vtilex_822.getType().hasName("int")
and vtiley_823.getType().hasName("int")
and vs_819.getType().hasName("Jpeg2000DecoderContext *")
and vtilex_822.getParentScope+() = func
and vtiley_823.getParentScope+() = func
and vs_819.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
