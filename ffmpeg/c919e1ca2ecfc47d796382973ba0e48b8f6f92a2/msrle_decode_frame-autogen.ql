/**
 * @name ffmpeg-c919e1ca2ecfc47d796382973ba0e48b8f6f92a2-msrle_decode_frame
 * @id cpp/ffmpeg/c919e1ca2ecfc47d796382973ba0e48b8f6f92a2/msrle-decode-frame
 * @description ffmpeg-c919e1ca2ecfc47d796382973ba0e48b8f6f92a2-libavcodec/msrle.c-msrle_decode_frame CVE-2014-2099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="7"
		and not target_0.getValue()="0"
		and target_0.getParent().(AddExpr).getParent().(DivExpr).getLeftOperand() instanceof AddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vavctx_84, DivExpr target_4) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("av_image_get_linesize")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_84
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_84
		and target_1.getArgument(2).(Literal).getValue()="0"
		and target_4.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vavctx_84, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="width"
		and target_2.getQualifier().(VariableAccess).getTarget()=vavctx_84
}

predicate func_3(Parameter vavctx_84, VariableAccess target_3) {
		target_3.getTarget()=vavctx_84
}

predicate func_4(Parameter vavctx_84, DivExpr target_4) {
		target_4.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_84
		and target_4.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_4.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_84
		and target_4.getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_4.getRightOperand().(Literal).getValue()="8"
}

from Function func, Parameter vavctx_84, Literal target_0, PointerFieldAccess target_2, VariableAccess target_3, DivExpr target_4
where
func_0(func, target_0)
and not func_1(vavctx_84, target_4)
and func_2(vavctx_84, target_2)
and func_3(vavctx_84, target_3)
and func_4(vavctx_84, target_4)
and vavctx_84.getType().hasName("AVCodecContext *")
and vavctx_84.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
