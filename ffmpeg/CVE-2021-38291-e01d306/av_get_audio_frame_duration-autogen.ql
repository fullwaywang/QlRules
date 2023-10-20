/**
 * @name ffmpeg-e01d306c647b5827102260b885faa223b646d2d1-av_get_audio_frame_duration
 * @id cpp/ffmpeg/e01d306c647b5827102260b885faa223b646d2d1/av-get-audio-frame-duration
 * @description ffmpeg-e01d306c647b5827102260b885faa223b646d2d1-libavcodec/utils.c-av_get_audio_frame_duration CVE-2021-38291
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(Literal).getValue()="0"
		and target_0.getElse().(VariableAccess).getType().hasName("int")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vavctx_811, Parameter vframe_bytes_811, FunctionCall target_1) {
		target_1.getTarget().hasName("get_audio_frame_duration")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="channels"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(3).(PointerFieldAccess).getTarget().getName()="block_align"
		and target_1.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(4).(PointerFieldAccess).getTarget().getName()="codec_tag"
		and target_1.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(5).(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_1.getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(6).(PointerFieldAccess).getTarget().getName()="bit_rate"
		and target_1.getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(7).(PointerFieldAccess).getTarget().getName()="extradata"
		and target_1.getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(8).(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_1.getArgument(8).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_811
		and target_1.getArgument(9).(VariableAccess).getTarget()=vframe_bytes_811
}

from Function func, Parameter vavctx_811, Parameter vframe_bytes_811, FunctionCall target_1
where
not func_0(func)
and func_1(vavctx_811, vframe_bytes_811, target_1)
and vavctx_811.getType().hasName("AVCodecContext *")
and vframe_bytes_811.getType().hasName("int")
and vavctx_811.getParentScope+() = func
and vframe_bytes_811.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
