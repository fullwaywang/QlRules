/**
 * @name ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-v4l2_decode_close
 * @id cpp/ffmpeg/7c32e9cf93b712f8463573a59ed4e98fd10fa013/v4l2-decode-close
 * @description ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-libavcodec/v4l2_m2m_dec.c-v4l2_decode_close CVE-2020-22038
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_217, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="priv_data"
		and target_0.getQualifier().(VariableAccess).getTarget()=vavctx_217
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vs_220, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_packet_unref")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf_pkt"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_220
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vpriv_219, VariableAccess target_4) {
		target_4.getTarget()=vpriv_219
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ff_v4l2_m2m_codec_end")
}

from Function func, Parameter vavctx_217, Variable vpriv_219, Variable vs_220, PointerFieldAccess target_0, DeclStmt target_1, DeclStmt target_2, ExprStmt target_3, VariableAccess target_4
where
func_0(vavctx_217, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(vs_220, func, target_3)
and func_4(vpriv_219, target_4)
and vavctx_217.getType().hasName("AVCodecContext *")
and vpriv_219.getType().hasName("V4L2m2mPriv *")
and vs_220.getType().hasName("V4L2m2mContext *")
and vavctx_217.getParentScope+() = func
and vpriv_219.getParentScope+() = func
and vs_220.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
