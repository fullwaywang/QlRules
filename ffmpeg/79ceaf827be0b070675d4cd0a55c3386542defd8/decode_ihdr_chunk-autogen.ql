/**
 * @name ffmpeg-79ceaf827be0b070675d4cd0a55c3386542defd8-decode_ihdr_chunk
 * @id cpp/ffmpeg/79ceaf827be0b070675d4cd0a55c3386542defd8/decode-ihdr-chunk
 * @description ffmpeg-79ceaf827be0b070675d4cd0a55c3386542defd8-libavcodec/pngdec.c-decode_ihdr_chunk CVE-2014-9317
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_522, Parameter vs_522, FunctionCall target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_522
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_522
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="IHDR after IDAT\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(3).(VariableAccess).getLocation())
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_522, Parameter vs_522, FunctionCall target_1) {
		target_1.getTarget().hasName("av_image_check_size")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_522
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_522
		and target_1.getArgument(2).(Literal).getValue()="0"
		and target_1.getArgument(3).(VariableAccess).getTarget()=vavctx_522
}

predicate func_2(Parameter vs_522, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_522
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_be32")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_522
}

from Function func, Parameter vavctx_522, Parameter vs_522, FunctionCall target_1, ExprStmt target_2
where
not func_0(vavctx_522, vs_522, target_1, target_2, func)
and func_1(vavctx_522, vs_522, target_1)
and func_2(vs_522, target_2)
and vavctx_522.getType().hasName("AVCodecContext *")
and vs_522.getType().hasName("PNGDecContext *")
and vavctx_522.getFunction() = func
and vs_522.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
