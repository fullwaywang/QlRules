/**
 * @name ffmpeg-a5d44d5c220e12ca0cb7a4eceb0f74759cb13111-sws_init_context
 * @id cpp/ffmpeg/a5d44d5c220e12ca0cb7a4eceb0f74759cb13111/sws-init-context
 * @description ffmpeg-a5d44d5c220e12ca0cb7a4eceb0f74759cb13111-libswscale/utils.c-sws_init_context CVE-2015-6824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_981, FunctionCall target_0) {
		target_0.getTarget().hasName("av_malloc")
		and not target_0.getTarget().hasName("av_mallocz")
		and target_0.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vLumBufSize"
		and target_0.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_981
		and target_0.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_0.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
}

predicate func_1(Parameter vc_981, FunctionCall target_1) {
		target_1.getTarget().hasName("av_malloc")
		and not target_1.getTarget().hasName("av_mallocz")
		and target_1.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vChrBufSize"
		and target_1.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_981
		and target_1.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_1.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
}

predicate func_2(Parameter vc_981, FunctionCall target_2) {
		target_2.getTarget().hasName("av_malloc")
		and not target_2.getTarget().hasName("av_mallocz")
		and target_2.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vChrBufSize"
		and target_2.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_981
		and target_2.getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_2.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
}

from Function func, Parameter vc_981, FunctionCall target_0, FunctionCall target_1, FunctionCall target_2
where
func_0(vc_981, target_0)
and func_1(vc_981, target_1)
and func_2(vc_981, target_2)
and vc_981.getType().hasName("SwsContext *")
and vc_981.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
