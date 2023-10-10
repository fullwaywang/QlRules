/**
 * @name ffmpeg-1f41cffe1e3e79620f587545bdfcbd7e6e68ed29-mjpeg_decode_scan_progressive_ac
 * @id cpp/ffmpeg/1f41cffe1e3e79620f587545bdfcbd7e6e68ed29/mjpeg-decode-scan-progressive-ac
 * @description ffmpeg-1f41cffe1e3e79620f587545bdfcbd7e6e68ed29-libavcodec/mjpegdec.c-mjpeg_decode_scan_progressive_ac CVE-2013-0854
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1087, Parameter vse_1088, ArrayExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vse_1088
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="63"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1087
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SE %d is too large\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vse_1088
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_1087, ArrayExpr target_1) {
		target_1.getArrayBase().(PointerFieldAccess).getTarget().getName()="quant_matrixes"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1087
		and target_1.getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="quant_index"
		and target_1.getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1087
		and target_1.getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_2(Parameter vs_1087, Parameter vse_1088, ExprStmt target_2) {
		target_2.getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coefs_finished"
		and target_2.getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1087
		and target_2.getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignOrExpr).getRValue().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignOrExpr).getRValue().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vse_1088
		and target_2.getExpr().(AssignOrExpr).getRValue().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignOrExpr).getRValue().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignOrExpr).getRValue().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vs_1087, Parameter vse_1088, ArrayExpr target_1, ExprStmt target_2
where
not func_0(vs_1087, vse_1088, target_1, target_2, func)
and func_1(vs_1087, target_1)
and func_2(vs_1087, vse_1088, target_2)
and vs_1087.getType().hasName("MJpegDecodeContext *")
and vse_1088.getType().hasName("int")
and vs_1087.getFunction() = func
and vse_1088.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
