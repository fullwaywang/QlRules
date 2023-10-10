/**
 * @name ffmpeg-229e4c133287955d5f3f837520a3602709b21950-decode_frame
 * @id cpp/ffmpeg/229e4c133287955d5f3f837520a3602709b21950/decode-frame
 * @description ffmpeg-229e4c133287955d5f3f837520a3602709b21950-libavcodec/indeo5.c-decode_frame CVE-2012-2779
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_744, Variable vresult_747, BlockStmt target_2, ExprStmt target_3, BitwiseAndExpr target_4, ExprStmt target_5) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vresult_747
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="gop_invalid"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_744
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Variable vresult_747, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vresult_747
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vresult_747, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error while decoding picture header: %d\n"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vresult_747
}

predicate func_3(Variable vctx_744, Variable vresult_747, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_747
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("decode_pic_hdr")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_744
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
}

predicate func_4(Variable vctx_744, BitwiseAndExpr target_4) {
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="gop_flags"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_744
		and target_4.getRightOperand().(Literal).getValue()="32"
}

predicate func_5(Variable vresult_747, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error while decoding picture header: %d\n"
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vresult_747
}

from Function func, Variable vctx_744, Variable vresult_747, VariableAccess target_1, BlockStmt target_2, ExprStmt target_3, BitwiseAndExpr target_4, ExprStmt target_5
where
not func_0(vctx_744, vresult_747, target_2, target_3, target_4, target_5)
and func_1(vresult_747, target_2, target_1)
and func_2(vresult_747, target_2)
and func_3(vctx_744, vresult_747, target_3)
and func_4(vctx_744, target_4)
and func_5(vresult_747, target_5)
and vctx_744.getType().hasName("IVI5DecContext *")
and vresult_747.getType().hasName("int")
and vctx_744.(LocalVariable).getFunction() = func
and vresult_747.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
