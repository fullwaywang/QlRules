/**
 * @name libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-jinit_write_ppm
 * @id cpp/libjpeg-turbo/5bc43c7821df982f65aa1c738f67fbf7cba8bd69/jinit-write-ppm
 * @description libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-wrppm.c-jinit_write_ppm CVE-2017-15232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="80"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vdest_206, ExprStmt target_9) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ValueFieldAccess).getTarget().getName()="calc_buffer_dimensions"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vcinfo_204, Variable vdest_206, ExprStmt target_11, ExprStmt target_13) {
	exists(VariableCall target_2 |
		target_2.getExpr().(ValueFieldAccess).getTarget().getName()="calc_buffer_dimensions"
		and target_2.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_2.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
		and target_2.getArgument(0).(VariableAccess).getTarget()=vcinfo_204
		and target_2.getArgument(1).(VariableAccess).getTarget()=vdest_206
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vdest_206, VariableAccess target_3) {
		target_3.getTarget()=vdest_206
}

predicate func_4(Variable vdest_206, VariableAccess target_4) {
		target_4.getTarget()=vdest_206
}

predicate func_5(Parameter vcinfo_204, VariableAccess target_5) {
		target_5.getTarget()=vcinfo_204
}

predicate func_6(Variable vdest_206, VariableAccess target_6) {
		target_6.getTarget()=vdest_206
}

predicate func_7(Parameter vcinfo_204, Variable vdest_206, AssignExpr target_7) {
		target_7.getLValue().(PointerFieldAccess).getTarget().getName()="samples_per_row"
		and target_7.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
		and target_7.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_width"
		and target_7.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_204
		and target_7.getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="out_color_components"
		and target_7.getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_204
}

predicate func_8(Variable vdest_206, AssignExpr target_8) {
		target_8.getLValue().(PointerFieldAccess).getTarget().getName()="buffer_width"
		and target_8.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
		and target_8.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="samples_per_row"
		and target_8.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
		and target_8.getRValue().(MulExpr).getRightOperand().(MulExpr).getValue()="1"
}

predicate func_9(Variable vdest_206, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="finish_output"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
}

predicate func_11(Parameter vcinfo_204, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("jpeg_calc_output_dimensions")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_204
}

predicate func_13(Parameter vcinfo_204, Variable vdest_206, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="iobuffer"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
		and target_13.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="alloc_small"
		and target_13.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mem"
		and target_13.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_204
		and target_13.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_204
		and target_13.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(Literal).getValue()="1"
		and target_13.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="buffer_width"
		and target_13.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_206
}

from Function func, Parameter vcinfo_204, Variable vdest_206, SizeofTypeOperator target_0, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, AssignExpr target_7, AssignExpr target_8, ExprStmt target_9, ExprStmt target_11, ExprStmt target_13
where
func_0(func, target_0)
and not func_1(vdest_206, target_9)
and not func_2(vcinfo_204, vdest_206, target_11, target_13)
and func_3(vdest_206, target_3)
and func_4(vdest_206, target_4)
and func_5(vcinfo_204, target_5)
and func_6(vdest_206, target_6)
and func_7(vcinfo_204, vdest_206, target_7)
and func_8(vdest_206, target_8)
and func_9(vdest_206, target_9)
and func_11(vcinfo_204, target_11)
and func_13(vcinfo_204, vdest_206, target_13)
and vcinfo_204.getType().hasName("j_decompress_ptr")
and vdest_206.getType().hasName("ppm_dest_ptr")
and vcinfo_204.getParentScope+() = func
and vdest_206.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
