/**
 * @name ffmpeg-58b2e0f0f2fc96c1158e04f8aba95cbe6157a1a3-vqa_decode_init
 * @id cpp/ffmpeg/58b2e0f0f2fc96c1158e04f8aba95cbe6157a1a3/vqa-decode-init
 * @description ffmpeg-58b2e0f0f2fc96c1158e04f8aba95cbe6157a1a3-libavcodec/vqavideo.c-vqa_decode_init CVE-2012-0947
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_121, Variable vs_123, FunctionCall target_1, LogicalOrExpr target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vector_width"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vector_height"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_121
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Image size not multiple of block size\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_1.getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_121, Variable vs_123, FunctionCall target_1) {
		target_1.getTarget().hasName("av_image_check_size")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_1.getArgument(2).(Literal).getValue()="0"
		and target_1.getArgument(3).(VariableAccess).getTarget()=vavctx_121
}

predicate func_2(Variable vs_123, LogicalOrExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vector_width"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vector_height"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vector_height"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_3(Variable vs_123, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="codebook_size"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_123
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getValue()="1048576"
}

from Function func, Parameter vavctx_121, Variable vs_123, FunctionCall target_1, LogicalOrExpr target_2, ExprStmt target_3
where
not func_0(vavctx_121, vs_123, target_1, target_2, target_3, func)
and func_1(vavctx_121, vs_123, target_1)
and func_2(vs_123, target_2)
and func_3(vs_123, target_3)
and vavctx_121.getType().hasName("AVCodecContext *")
and vs_123.getType().hasName("VqaContext *")
and vavctx_121.getFunction() = func
and vs_123.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
