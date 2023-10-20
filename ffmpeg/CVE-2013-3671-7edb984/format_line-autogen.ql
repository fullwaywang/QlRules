/**
 * @name ffmpeg-7edb984dd051b6919d7d8471c70499273f31b0fa-format_line
 * @id cpp/ffmpeg/7edb984dd051b6919d7d8471c70499273f31b0fa/format-line
 * @description ffmpeg-7edb984dd051b6919d7d8471c70499273f31b0fa-libavutil/log.c-format_line CVE-2013-3671
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vavc_173, Parameter vptr_170, PointerDereferenceExpr target_2, VariableCall target_3, PointerArithmeticOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vptr_170
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="parent_log_context_offset"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavc_173
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_category")
		and target_2.getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Variable vavc_173, Parameter vptr_170, PointerDereferenceExpr target_2) {
		target_2.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_170
		and target_2.getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent_log_context_offset"
		and target_2.getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavc_173
}

predicate func_3(Variable vavc_173, Parameter vptr_170, VariableCall target_3) {
		target_3.getExpr().(PointerFieldAccess).getTarget().getName()="item_name"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavc_173
		and target_3.getArgument(0).(VariableAccess).getTarget()=vptr_170
}

from Function func, Variable vavc_173, Parameter vptr_170, PointerArithmeticOperation target_1, PointerDereferenceExpr target_2, VariableCall target_3
where
func_1(vavc_173, vptr_170, target_2, target_3, target_1)
and func_2(vavc_173, vptr_170, target_2)
and func_3(vavc_173, vptr_170, target_3)
and vavc_173.getType().hasName("AVClass *")
and vptr_170.getType().hasName("void *")
and vavc_173.(LocalVariable).getFunction() = func
and vptr_170.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
