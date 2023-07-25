/**
 * @name ffmpeg-d270c3202539e8364c46410e15f7570800e33343-avcodec_decode_audio4
 * @id cpp/ffmpeg/d270c3202539e8364c46410e15f7570800e33343/avcodec-decode-audio4
 * @description ffmpeg-d270c3202539e8364c46410e15f7570800e33343-libavcodec/utils.c-avcodec_decode_audio4 CVE-2013-0861
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vframe_1717, ExprStmt target_3, ExprStmt target_4) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="channels"
		and target_0.getQualifier().(VariableAccess).getTarget()=vframe_1717
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vframe_1717, VariableAccess target_1) {
		target_1.getTarget()=vframe_1717
		and target_1.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_2(Parameter vframe_1717, FunctionCall target_2) {
		target_2.getTarget().hasName("av_get_channel_layout_nb_channels")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="channel_layout"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_1717
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vframe_1717, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_sample_fmt_is_planar")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_1717
}

predicate func_4(Parameter vframe_1717, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extended_data"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_1717
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_1717
}

from Function func, Parameter vframe_1717, VariableAccess target_1, FunctionCall target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vframe_1717, target_3, target_4)
and func_1(vframe_1717, target_1)
and func_2(vframe_1717, target_2)
and func_3(vframe_1717, target_3)
and func_4(vframe_1717, target_4)
and vframe_1717.getType().hasName("AVFrame *")
and vframe_1717.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
