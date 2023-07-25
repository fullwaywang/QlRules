/**
 * @name ffmpeg-23318a57358358e7a4dc551e830e4503f0638cfe-ff_er_frame_end
 * @id cpp/ffmpeg/23318a57358358e7a4dc551e830e4503f0638cfe/ff-er-frame-end
 * @description ffmpeg-23318a57358358e7a4dc551e830e4503f0638cfe-libavcodec/error_resilience.c-ff_er_frame_end CVE-2013-0860
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_906, LogicalOrExpr target_1, ValueFieldAccess target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="picture_structure"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="linesize"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="f"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="current_picture"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="linesize"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="f"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="current_picture_ptr"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error concealment not possible, frame not fully initialized\n"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_906, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lowres"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="capabilities"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codec"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="128"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="picture_structure"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="error_count"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="mb_width"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="skip_top"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="skip_bottom"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
}

predicate func_2(Parameter vs_906, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="f"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="current_picture"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_906
}

from Function func, Parameter vs_906, LogicalOrExpr target_1, ValueFieldAccess target_2
where
not func_0(vs_906, target_1, target_2, func)
and func_1(vs_906, target_1)
and func_2(vs_906, target_2)
and vs_906.getType().hasName("MpegEncContext *")
and vs_906.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
