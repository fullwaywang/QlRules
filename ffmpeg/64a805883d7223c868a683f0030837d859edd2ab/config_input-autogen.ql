/**
 * @name ffmpeg-64a805883d7223c868a683f0030837d859edd2ab-config_input
 * @id cpp/ffmpeg/64a805883d7223c868a683f0030837d859edd2ab/config-input
 * @description ffmpeg-64a805883d7223c868a683f0030837d859edd2ab-libavfilter/vf_gblur.c-config_input CVE-2020-20891
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinlink_226, ExprStmt target_4) {
	exists(BitwiseAndExpr target_0 |
		target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="w"
		and target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_0.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getRightOperand().(ComplementExpr).getValue()="-16"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc_array")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="w"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vinlink_226, ExprStmt target_5) {
	exists(BitwiseAndExpr target_1 |
		target_1.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_1.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_1.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_1.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getRightOperand().(ComplementExpr).getValue()="-16"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vinlink_226, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="w"
		and target_2.getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc_array")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
}

/*predicate func_3(Parameter vinlink_226, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="h"
		and target_3.getQualifier().(VariableAccess).getTarget()=vinlink_226
}

*/
predicate func_4(Parameter vinlink_226, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nb_planes"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_pix_fmt_count_planes")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
}

predicate func_5(Parameter vinlink_226, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc_array")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="w"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_226
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
}

from Function func, Parameter vinlink_226, PointerFieldAccess target_2, ExprStmt target_4, ExprStmt target_5
where
not func_0(vinlink_226, target_4)
and not func_1(vinlink_226, target_5)
and func_2(vinlink_226, target_2)
and func_4(vinlink_226, target_4)
and func_5(vinlink_226, target_5)
and vinlink_226.getType().hasName("AVFilterLink *")
and vinlink_226.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
