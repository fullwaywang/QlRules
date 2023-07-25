/**
 * @name ffmpeg-a7a7f32c8ad0179a1a85d0a8cff35924e6d90be8-aac_encode_frame
 * @id cpp/ffmpeg/a7a7f32c8ad0179a1a85d0a8cff35924e6d90be8/aac-encode-frame
 * @description ffmpeg-a7a7f32c8ad0179a1a85d0a8cff35924e6d90be8-libavcodec/aacenc.c-aac_encode_frame CVE-2020-20453
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="65536.0"
		and not target_0.getValue()="1.175494351e-38"
		and target_0.getParent().(ConditionalExpr).getParent().(AssignExpr).getRValue() instanceof ConditionalExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("av_clipf_sse")
		and target_1.getArgument(0) instanceof MulExpr
		and target_1.getArgument(1).(Literal).getValue()="1.175494351e-38"
		and target_1.getArgument(2) instanceof Literal
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vs_556, Variable vratio_840, MulExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lambda"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_556
		and target_2.getRightOperand().(VariableAccess).getTarget()=vratio_840
		and target_2.getParent().(GTExpr).getLesserOperand().(Literal).getValue()="65536.0"
}

predicate func_4(Variable vs_556, Variable vratio_840, ConditionalExpr target_4) {
		target_4.getCondition().(RelationalOperation).getGreaterOperand() instanceof MulExpr
		and target_4.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_4.getThen() instanceof Literal
		and target_4.getElse().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="lambda"
		and target_4.getElse().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_556
		and target_4.getElse().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vratio_840
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lambda"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_556
}

from Function func, Variable vs_556, Variable vratio_840, Literal target_0, MulExpr target_2, ConditionalExpr target_4
where
func_0(func, target_0)
and not func_1(func)
and func_2(vs_556, vratio_840, target_2)
and func_4(vs_556, vratio_840, target_4)
and vs_556.getType().hasName("AACEncContext *")
and vratio_840.getType().hasName("float")
and vs_556.getParentScope+() = func
and vratio_840.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
