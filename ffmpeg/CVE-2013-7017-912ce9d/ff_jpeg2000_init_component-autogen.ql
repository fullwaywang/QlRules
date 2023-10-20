/**
 * @name ffmpeg-912ce9dd2080c5837285a471d750fa311e09b555-ff_jpeg2000_init_component
 * @id cpp/ffmpeg/912ce9dd2080c5837285a471d750fa311e09b555/ff-jpeg2000-init-component
 * @description ffmpeg-912ce9dd2080c5837285a471d750fa311e09b555-libavcodec/jpeg2000.c-ff_jpeg2000_init_component CVE-2013-7017
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vreslevel_233, FunctionCall target_0) {
		target_0.getTarget().hasName("av_malloc_array")
		and not target_0.getTarget().hasName("av_calloc")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="nbands"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreslevel_233
		and target_0.getArgument(1).(SizeofExprOperator).getValue()="32"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="band"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreslevel_233
}

predicate func_1(Variable vreslevel_233, FunctionCall target_1) {
		target_1.getTarget().hasName("av_malloc_array")
		and not target_1.getTarget().hasName("av_calloc")
		and target_1.getArgument(0).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_precincts_x"
		and target_1.getArgument(0).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreslevel_233
		and target_1.getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="num_precincts_y"
		and target_1.getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreslevel_233
		and target_1.getArgument(1).(SizeofExprOperator).getValue()="40"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="prec"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Jpeg2000Band *")
}

from Function func, Variable vreslevel_233, FunctionCall target_0, FunctionCall target_1
where
func_0(vreslevel_233, target_0)
and func_1(vreslevel_233, target_1)
and vreslevel_233.getType().hasName("Jpeg2000ResLevel *")
and vreslevel_233.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
