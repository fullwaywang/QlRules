/**
 * @name ffmpeg-96f452ac647dae33c53c242ef3266b65a9beafb6-aac_decode_init
 * @id cpp/ffmpeg/96f452ac647dae33c53c242ef3266b65a9beafb6/aac-decode-init
 * @description ffmpeg-96f452ac647dae33c53c242ef3266b65a9beafb6-libavcodec/aacdec.c-aac_decode_init CVE-2013-0866
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_873, BitwiseAndExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_873
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="64"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_873
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Too many channels\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_873, BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="err_recognition"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_873
		and target_1.getRightOperand().(BinaryBitwiseOperation).getValue()="8"
}

predicate func_2(Parameter vavctx_873, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ff_fmt_convert_init")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fmt_conv"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AACContext *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vavctx_873
}

from Function func, Parameter vavctx_873, BitwiseAndExpr target_1, ExprStmt target_2
where
not func_0(vavctx_873, target_1, target_2, func)
and func_1(vavctx_873, target_1)
and func_2(vavctx_873, target_2)
and vavctx_873.getType().hasName("AVCodecContext *")
and vavctx_873.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
