/**
 * @name ffmpeg-47f4e2d8960ca756ca153ab8e3e93d80449b8c91-decode_ihdr_chunk
 * @id cpp/ffmpeg/47f4e2d8960ca756ca153ab8e3e93d80449b8c91/decode-ihdr-chunk
 * @description ffmpeg-47f4e2d8960ca756ca153ab8e3e93d80449b8c91-libavcodec/pngdec.c-decode_ihdr_chunk CVE-2015-6818
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_534, Parameter vs_534, ExprStmt target_1, FunctionCall target_2, BitwiseAndExpr target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_534
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_534
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Multiple IHDR\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getArgument(3).(VariableAccess).getLocation())
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_534, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_534
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="IHDR after IDAT\n"
}

predicate func_2(Parameter vavctx_534, Parameter vs_534, FunctionCall target_2) {
		target_2.getTarget().hasName("av_image_check_size")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_534
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_534
		and target_2.getArgument(2).(Literal).getValue()="0"
		and target_2.getArgument(3).(VariableAccess).getTarget()=vavctx_534
}

predicate func_3(Parameter vs_534, BitwiseAndExpr target_3) {
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_534
		and target_3.getRightOperand().(Literal).getValue()="2"
}

predicate func_4(Parameter vs_534, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_534
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_be32")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_534
}

from Function func, Parameter vavctx_534, Parameter vs_534, ExprStmt target_1, FunctionCall target_2, BitwiseAndExpr target_3, ExprStmt target_4
where
not func_0(vavctx_534, vs_534, target_1, target_2, target_3, target_4, func)
and func_1(vavctx_534, target_1)
and func_2(vavctx_534, vs_534, target_2)
and func_3(vs_534, target_3)
and func_4(vs_534, target_4)
and vavctx_534.getType().hasName("AVCodecContext *")
and vs_534.getType().hasName("PNGDecContext *")
and vavctx_534.getFunction() = func
and vs_534.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
