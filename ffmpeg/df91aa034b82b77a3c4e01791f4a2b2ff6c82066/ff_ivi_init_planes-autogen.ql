/**
 * @name ffmpeg-df91aa034b82b77a3c4e01791f4a2b2ff6c82066-ff_ivi_init_planes
 * @id cpp/ffmpeg/df91aa034b82b77a3c4e01791f4a2b2ff6c82066/ff-ivi-init-planes
 * @description ffmpeg-df91aa034b82b77a3c4e01791f4a2b2ff6c82066-libavcodec/ivi.c-ff_ivi_init_planes CVE-2015-8364
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcfg_303, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="pic_width"
		and target_0.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_303
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vcfg_303, LogicalOrExpr target_7) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("av_image_check_size")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="pic_width"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_303
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="pic_height"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_303
		and target_2.getArgument(2).(Literal).getValue()="0"
		and target_2.getArgument(3).(Literal).getValue()="0"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vcfg_303, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="pic_width"
		and target_4.getQualifier().(VariableAccess).getTarget()=vcfg_303
}

predicate func_5(Parameter vcfg_303, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="pic_height"
		and target_5.getQualifier().(VariableAccess).getTarget()=vcfg_303
}

predicate func_6(Parameter vcfg_303, LogicalOrExpr target_6) {
		target_6.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="pic_width"
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_303
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="pic_height"
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_303
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
}

predicate func_7(Parameter vcfg_303, LogicalOrExpr target_7) {
		target_7.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="luma_bands"
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_303
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="chroma_bands"
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_303
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
}

from Function func, Parameter vcfg_303, Literal target_0, Literal target_1, PointerFieldAccess target_4, PointerFieldAccess target_5, LogicalOrExpr target_6, LogicalOrExpr target_7
where
func_0(vcfg_303, target_0)
and func_1(func, target_1)
and not func_2(vcfg_303, target_7)
and func_4(vcfg_303, target_4)
and func_5(vcfg_303, target_5)
and func_6(vcfg_303, target_6)
and func_7(vcfg_303, target_7)
and vcfg_303.getType().hasName("const IVIPicConfig *")
and vcfg_303.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
