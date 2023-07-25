/**
 * @name ffmpeg-4931c8f0f10bf8dedcf626104a6b85bfefadc6f2-svq1_decode_frame
 * @id cpp/ffmpeg/4931c8f0f10bf8dedcf626104a6b85bfefadc6f2/svq1-decode-frame
 * @description ffmpeg-4931c8f0f10bf8dedcf626104a6b85bfefadc6f2-libavcodec/svq1dec.c-svq1_decode_frame CVE-2011-4579
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_630, Parameter vavctx_624, ExprStmt target_1, LogicalAndExpr target_2, LogicalOrExpr target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("avcodec_set_dimensions")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_624
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_630
		and target_0.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_630
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_630, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_630
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error in svq1_decode_frame_header %i\n"
		and target_1.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_2(Variable vs_630, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pict_type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_630
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="last_picture_ptr"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_630
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vs_630, Parameter vavctx_624, LogicalOrExpr target_3) {
		target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="skip_frame"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_624
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pict_type"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_630
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="skip_frame"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_624
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pict_type"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_630
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="skip_frame"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_624
}

from Function func, Variable vs_630, Parameter vavctx_624, ExprStmt target_1, LogicalAndExpr target_2, LogicalOrExpr target_3
where
not func_0(vs_630, vavctx_624, target_1, target_2, target_3, func)
and func_1(vs_630, target_1)
and func_2(vs_630, target_2)
and func_3(vs_630, vavctx_624, target_3)
and vs_630.getType().hasName("MpegEncContext *")
and vavctx_624.getType().hasName("AVCodecContext *")
and vs_630.(LocalVariable).getFunction() = func
and vavctx_624.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
