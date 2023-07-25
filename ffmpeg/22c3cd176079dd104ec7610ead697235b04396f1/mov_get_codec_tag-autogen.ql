/**
 * @name ffmpeg-22c3cd176079dd104ec7610ead697235b04396f1-mov_get_codec_tag
 * @id cpp/ffmpeg/22c3cd176079dd104ec7610ead697235b04396f1/mov-get-codec-tag
 * @description ffmpeg-22c3cd176079dd104ec7610ead697235b04396f1-libavformat/movenc.c-mov_get_codec_tag CVE-2020-21688
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtag_1654, LogicalOrExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtag_1654
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="544240754"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtag_1654
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtag_1654, LogicalOrExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vtag_1654
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="strict_std_compliance"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("av_get_bits_per_sample")
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
}

from Function func, Variable vtag_1654, LogicalOrExpr target_1
where
not func_0(vtag_1654, target_1, func)
and func_1(vtag_1654, target_1)
and vtag_1654.getType().hasName("unsigned int")
and vtag_1654.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
