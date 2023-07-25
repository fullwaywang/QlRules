/**
 * @name ffmpeg-951cbea56fdc03ef96d07fbd7e5bed755d42ac8a-mpeg_decode_frame
 * @id cpp/ffmpeg/951cbea56fdc03ef96d07fbd7e5bed755d42ac8a/mpeg-decode-frame
 * @description ffmpeg-951cbea56fdc03ef96d07fbd7e5bed755d42ac8a-libavcodec/mpeg12.c-mpeg_decode_frame CVE-2012-2803
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_size_2254, LogicalAndExpr target_1, FunctionCall target_2, FunctionCall target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_size_2254
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(LogicalAndExpr target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame_number"
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
}

predicate func_2(Parameter vdata_size_2254, FunctionCall target_2) {
		target_2.getTarget().hasName("decode_chunks")
		and target_2.getArgument(0).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_2.getArgument(1).(VariableAccess).getTarget().getType().hasName("AVFrame *")
		and target_2.getArgument(2).(VariableAccess).getTarget()=vdata_size_2254
		and target_2.getArgument(3).(PointerFieldAccess).getTarget().getName()="extradata"
		and target_2.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_2.getArgument(4).(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_2.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
}

predicate func_3(Parameter vdata_size_2254, FunctionCall target_3) {
		target_3.getTarget().hasName("decode_chunks")
		and target_3.getArgument(0).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_3.getArgument(1).(VariableAccess).getTarget().getType().hasName("AVFrame *")
		and target_3.getArgument(2).(VariableAccess).getTarget()=vdata_size_2254
		and target_3.getArgument(3).(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_3.getArgument(4).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vdata_size_2254, LogicalAndExpr target_1, FunctionCall target_2, FunctionCall target_3
where
not func_0(vdata_size_2254, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vdata_size_2254, target_2)
and func_3(vdata_size_2254, target_3)
and vdata_size_2254.getType().hasName("int *")
and vdata_size_2254.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
