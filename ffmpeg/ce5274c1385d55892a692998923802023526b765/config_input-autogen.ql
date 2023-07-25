/**
 * @name ffmpeg-ce5274c1385d55892a692998923802023526b765-config_input
 * @id cpp/ffmpeg/ce5274c1385d55892a692998923802023526b765/config-input
 * @description ffmpeg-ce5274c1385d55892a692998923802023526b765-libavfilter/vf_fieldmatch.c-config_input CVE-2020-22020
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfm_936, FunctionCall target_0) {
		target_0.getTarget().hasName("av_malloc")
		and not target_0.getTarget().hasName("av_calloc")
		and target_0.getArgument(0).(MulExpr).getLeftOperand() instanceof DivExpr
		and target_0.getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tpitchy"
		and target_0.getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfm_936
}

predicate func_1(Function func) {
	exists(AddExpr target_1 |
		target_1.getAnOperand() instanceof DivExpr
		and target_1.getAnOperand().(Literal).getValue()="4"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(SizeofExprOperator target_2 |
		target_2.getValue()="1"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vh_939, DivExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vh_939
		and target_3.getRightOperand().(Literal).getValue()="2"
}

from Function func, Variable vfm_936, Variable vh_939, FunctionCall target_0, DivExpr target_3
where
func_0(vfm_936, target_0)
and not func_1(func)
and not func_2(func)
and func_3(vh_939, target_3)
and vfm_936.getType().hasName("FieldMatchContext *")
and vh_939.getType().hasName("const int")
and vfm_936.getParentScope+() = func
and vh_939.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
