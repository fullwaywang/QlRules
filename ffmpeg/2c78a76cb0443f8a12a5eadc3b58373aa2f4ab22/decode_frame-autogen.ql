/**
 * @name ffmpeg-2c78a76cb0443f8a12a5eadc3b58373aa2f4ab22-decode_frame
 * @id cpp/ffmpeg/2c78a76cb0443f8a12a5eadc3b58373aa2f4ab22/decode-frame
 * @description ffmpeg-2c78a76cb0443f8a12a5eadc3b58373aa2f4ab22-libavcodec/g729dec.c-decode_frame CVE-2020-20902
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_404, Variable vpitch_delay_int_415, ExprStmt target_2, PointerArithmeticOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="40"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpitch_delay_int_415
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_404
		and target_0.getThen() instanceof ExprStmt
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_404, Variable vctx_408, Variable vpitch_delay_int_415, Variable vfc_417, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("ff_acelp_weighted_vector_sum")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfc_417
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpitch_delay_int_415
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_404
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vfc_417
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpitch_delay_int_415
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_404
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfc_417
		and target_1.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getValue()="16384"
		and target_1.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("av_clip_c")
		and target_1.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="past_gain_pitch"
		and target_1.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_408
		and target_1.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(Literal).getValue()="3277"
		and target_1.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(2).(Literal).getValue()="13017"
		and target_1.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(6).(Literal).getValue()="14"
		and target_1.getExpr().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(Literal).getValue()="40"
		and target_1.getExpr().(FunctionCall).getArgument(7).(SubExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpitch_delay_int_415
		and target_1.getExpr().(FunctionCall).getArgument(7).(SubExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_404
}

predicate func_2(Variable vi_404, Variable vpitch_delay_int_415, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpitch_delay_int_415
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_404
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="143"
}

predicate func_3(Variable vi_404, Variable vpitch_delay_int_415, Variable vfc_417, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vfc_417
		and target_3.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpitch_delay_int_415
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_404
}

from Function func, Variable vi_404, Variable vctx_408, Variable vpitch_delay_int_415, Variable vfc_417, ExprStmt target_1, ExprStmt target_2, PointerArithmeticOperation target_3
where
not func_0(vi_404, vpitch_delay_int_415, target_2, target_3)
and func_1(vi_404, vctx_408, vpitch_delay_int_415, vfc_417, target_1)
and func_2(vi_404, vpitch_delay_int_415, target_2)
and func_3(vi_404, vpitch_delay_int_415, vfc_417, target_3)
and vi_404.getType().hasName("int")
and vctx_408.getType().hasName("G729ChannelContext *")
and vpitch_delay_int_415.getType().hasName("int[2]")
and vfc_417.getType().hasName("int16_t[40]")
and vi_404.getParentScope+() = func
and vctx_408.getParentScope+() = func
and vpitch_delay_int_415.getParentScope+() = func
and vfc_417.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
