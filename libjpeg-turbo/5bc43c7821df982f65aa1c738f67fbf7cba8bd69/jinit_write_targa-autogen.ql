/**
 * @name libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-jinit_write_targa
 * @id cpp/libjpeg-turbo/5bc43c7821df982f65aa1c738f67fbf7cba8bd69/jinit-write-targa
 * @description libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-wrtarga.c-jinit_write_targa CVE-2017-15232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="64"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vdest_221, ExprStmt target_6) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ValueFieldAccess).getTarget().getName()="calc_buffer_dimensions"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_221
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vcinfo_219, Variable vdest_221, ExprStmt target_7, ExprStmt target_9, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="calc_buffer_dimensions"
		and target_2.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_2.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_221
		and target_2.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_219
		and target_2.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vdest_221
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2)
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vdest_221, VariableAccess target_3) {
		target_3.getTarget()=vdest_221
}

predicate func_4(Parameter vcinfo_219, VariableAccess target_4) {
		target_4.getTarget()=vcinfo_219
}

predicate func_5(Parameter vcinfo_219, Variable vdest_221, AssignExpr target_5) {
		target_5.getLValue().(PointerFieldAccess).getTarget().getName()="buffer_width"
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_221
		and target_5.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_width"
		and target_5.getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_219
		and target_5.getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="output_components"
		and target_5.getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_219
}

predicate func_6(Variable vdest_221, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="finish_output"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_221
}

predicate func_7(Parameter vcinfo_219, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("jpeg_calc_output_dimensions")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_219
}

predicate func_9(Parameter vcinfo_219, Variable vdest_221, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="iobuffer"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_221
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="alloc_small"
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mem"
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_219
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_219
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(Literal).getValue()="1"
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="buffer_width"
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_221
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
}

from Function func, Parameter vcinfo_219, Variable vdest_221, SizeofTypeOperator target_0, VariableAccess target_3, VariableAccess target_4, AssignExpr target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_9
where
func_0(func, target_0)
and not func_1(vdest_221, target_6)
and not func_2(vcinfo_219, vdest_221, target_7, target_9, func)
and func_3(vdest_221, target_3)
and func_4(vcinfo_219, target_4)
and func_5(vcinfo_219, vdest_221, target_5)
and func_6(vdest_221, target_6)
and func_7(vcinfo_219, target_7)
and func_9(vcinfo_219, vdest_221, target_9)
and vcinfo_219.getType().hasName("j_decompress_ptr")
and vdest_221.getType().hasName("tga_dest_ptr")
and vcinfo_219.getParentScope+() = func
and vdest_221.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
