/**
 * @name ffmpeg-4ea4d2f438c9a7eba37980c9a87be4b34943e4d5-h264_slice_header_init
 * @id cpp/ffmpeg/4ea4d2f438c9a7eba37980c9a87be4b34943e4d5/h264-slice-header-init
 * @description ffmpeg-4ea4d2f438c9a7eba37980c9a87be4b34943e4d5-libavcodec/h264_slice.c-h264_slice_header_init CVE-2015-8661
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnb_slices_1025, Parameter vh_1023, ExprStmt target_1, LogicalOrExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="max_contexts"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_1023
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="max_contexts"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_1023
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnb_slices_1025
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vnb_slices_1025
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="max_contexts"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_1023
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnb_slices_1025, Parameter vh_1023, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="slice_context_count"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_1023
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnb_slices_1025
}

predicate func_2(Parameter vh_1023, LogicalOrExpr target_2) {
		target_2.getAnOperand().(NotExpr).getValue()="0"
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="active_thread_type"
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_1023
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Variable vnb_slices_1025, Parameter vh_1023, ExprStmt target_1, LogicalOrExpr target_2
where
not func_0(vnb_slices_1025, vh_1023, target_1, target_2, func)
and func_1(vnb_slices_1025, vh_1023, target_1)
and func_2(vh_1023, target_2)
and vnb_slices_1025.getType().hasName("int")
and vh_1023.getType().hasName("H264Context *")
and vnb_slices_1025.getParentScope+() = func
and vh_1023.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
