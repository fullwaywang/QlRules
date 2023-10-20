/**
 * @name ffmpeg-b288a7eb3d963a175e177b6219c8271076ee8590-mpeg_mux_end
 * @id cpp/ffmpeg/b288a7eb3d963a175e177b6219c8271076ee8590/mpeg-mux-end
 * @description ffmpeg-b288a7eb3d963a175e177b6219c8271076ee8590-libavformat/mpegenc.c-mpeg_mux_end CVE-2020-22043
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstream_1237, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("av_fifo_freep")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fifo"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1237
}

from Function func, Variable vstream_1237, ExprStmt target_0
where
func_0(vstream_1237, target_0)
and vstream_1237.getType().hasName("StreamInfo *")
and vstream_1237.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
