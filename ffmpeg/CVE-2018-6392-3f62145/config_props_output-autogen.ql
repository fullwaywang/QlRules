/**
 * @name ffmpeg-3f621455d62e46745453568d915badd5b1e5bcd5-config_props_output
 * @id cpp/ffmpeg/3f621455d62e46745453568d915badd5b1e5bcd5/config-props-output
 * @description ffmpeg-3f621455d62e46745453568d915badd5b1e5bcd5-libavfilter/vf_transpose.c-config_props_output CVE-2018-6392
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voutlink_193, FunctionCall target_2, ExprStmt target_3) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("av_pix_fmt_count_planes")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutlink_193
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdesc_in_199, ExprStmt target_4, NotExpr target_5, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="nb_components"
		and target_1.getQualifier().(VariableAccess).getTarget()=vdesc_in_199
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Parameter voutlink_193, FunctionCall target_2) {
		target_2.getTarget().hasName("av_pix_fmt_desc_get")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutlink_193
}

predicate func_3(Parameter voutlink_193, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutlink_193
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="h"
}

predicate func_4(Variable vdesc_in_199, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vsub"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="log2_chroma_h"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_in_199
}

predicate func_5(Variable vdesc_in_199, NotExpr target_5) {
		target_5.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nb_components"
		and target_5.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_in_199
		and target_5.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nb_components"
}

from Function func, Variable vdesc_in_199, Parameter voutlink_193, PointerFieldAccess target_1, FunctionCall target_2, ExprStmt target_3, ExprStmt target_4, NotExpr target_5
where
not func_0(voutlink_193, target_2, target_3)
and func_1(vdesc_in_199, target_4, target_5, target_1)
and func_2(voutlink_193, target_2)
and func_3(voutlink_193, target_3)
and func_4(vdesc_in_199, target_4)
and func_5(vdesc_in_199, target_5)
and vdesc_in_199.getType().hasName("const AVPixFmtDescriptor *")
and voutlink_193.getType().hasName("AVFilterLink *")
and vdesc_in_199.getParentScope+() = func
and voutlink_193.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
