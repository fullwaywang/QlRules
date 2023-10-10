/**
 * @name ffmpeg-1d3a3b9f8907625b361420d48fe05716859620ff-raw_decode
 * @id cpp/ffmpeg/1d3a3b9f8907625b361420d48fe05716859620ff/raw-decode
 * @description ffmpeg-1d3a3b9f8907625b361420d48fe05716859620ff-libavcodec/rawdec.c-raw_decode CVE-2014-9318
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcontext_153, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_153
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_153
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcontext_153, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_153
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avpicture_get_size")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
}

predicate func_2(Variable vcontext_153, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="is_2_4_bpp"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_153
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="is_yuv2"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_153
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="is_lt_16bpp"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_153
}

from Function func, Variable vcontext_153, ExprStmt target_1, ExprStmt target_2
where
not func_0(vcontext_153, target_1, target_2, func)
and func_1(vcontext_153, target_1)
and func_2(vcontext_153, target_2)
and vcontext_153.getType().hasName("RawVideoContext *")
and vcontext_153.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
