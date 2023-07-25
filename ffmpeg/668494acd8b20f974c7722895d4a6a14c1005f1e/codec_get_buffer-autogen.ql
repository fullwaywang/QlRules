/**
 * @name ffmpeg-668494acd8b20f974c7722895d4a6a14c1005f1e-codec_get_buffer
 * @id cpp/ffmpeg/668494acd8b20f974c7722895d4a6a14c1005f1e/codec-get-buffer
 * @description ffmpeg-668494acd8b20f974c7722895d4a6a14c1005f1e-ffmpeg.c-codec_get_buffer CVE-2011-3935
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_543, LogicalAndExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("av_image_check_size")
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_543
		and target_0.getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_543
		and target_0.getCondition().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vs_543
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_543, LogicalAndExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buffer_pool"
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("InputStream *")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("alloc_buffer")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_543
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("InputStream *")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buffer_pool"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("InputStream *")
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vs_543, LogicalAndExpr target_1
where
not func_0(vs_543, target_1, func)
and func_1(vs_543, target_1)
and vs_543.getType().hasName("AVCodecContext *")
and vs_543.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
