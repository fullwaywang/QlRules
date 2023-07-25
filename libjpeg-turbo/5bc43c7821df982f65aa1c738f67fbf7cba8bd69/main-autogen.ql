/**
 * @name libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-main
 * @id cpp/libjpeg-turbo/5bc43c7821df982f65aa1c738f67fbf7cba8bd69/main
 * @description libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-djpeg.c-main CVE-2017-15232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdest_mgr_501, PointerDereferenceExpr target_6) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="calc_buffer_dimensions"
		and target_0.getQualifier().(VariableAccess).getTarget()=vdest_mgr_501
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcinfo_495, Variable vdest_mgr_501, AddressOfExpr target_7, ExprStmt target_9) {
	exists(ExprCall target_1 |
		target_1.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="calc_buffer_dimensions"
		and target_1.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_mgr_501
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcinfo_495
		and target_1.getArgument(1).(VariableAccess).getTarget()=vdest_mgr_501
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_9.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdest_mgr_501, VariableAccess target_2) {
		target_2.getTarget()=vdest_mgr_501
}

predicate func_3(Variable vcinfo_495, VariableAccess target_3) {
		target_3.getTarget()=vcinfo_495
}

predicate func_4(Variable vrequested_fmt, ExprStmt target_11, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vrequested_fmt
		and target_4.getParent().(IfStmt).getThen()=target_11
}

predicate func_5(Variable vcinfo_495, Variable vdest_mgr_501, AssignExpr target_5) {
		target_5.getLValue().(PointerFieldAccess).getTarget().getName()="buffer_width"
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_mgr_501
		and target_5.getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="output_width"
		and target_5.getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_495
		and target_5.getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="out_color_components"
		and target_5.getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_495
		and target_5.getRValue().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getRValue().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
}

predicate func_6(Variable vdest_mgr_501, PointerDereferenceExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="start_output"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_mgr_501
}

predicate func_7(Variable vcinfo_495, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vcinfo_495
}

predicate func_9(Variable vcinfo_495, Variable vdest_mgr_501, ExprStmt target_9) {
		target_9.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="put_pixel_rows"
		and target_9.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_mgr_501
		and target_9.getExpr().(ExprCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcinfo_495
		and target_9.getExpr().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vdest_mgr_501
}

predicate func_11(Variable vcinfo_495, ExprStmt target_11) {
		target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="msg_code"
		and target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="err"
		and target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcinfo_495
		and target_11.getExpr().(CommaExpr).getRightOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="error_exit"
		and target_11.getExpr().(CommaExpr).getRightOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="err"
		and target_11.getExpr().(CommaExpr).getRightOperand().(ExprCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcinfo_495
}

from Function func, Variable vcinfo_495, Variable vdest_mgr_501, Variable vrequested_fmt, VariableAccess target_2, VariableAccess target_3, EqualityOperation target_4, AssignExpr target_5, PointerDereferenceExpr target_6, AddressOfExpr target_7, ExprStmt target_9, ExprStmt target_11
where
not func_0(vdest_mgr_501, target_6)
and not func_1(vcinfo_495, vdest_mgr_501, target_7, target_9)
and func_2(vdest_mgr_501, target_2)
and func_3(vcinfo_495, target_3)
and func_4(vrequested_fmt, target_11, target_4)
and func_5(vcinfo_495, vdest_mgr_501, target_5)
and func_6(vdest_mgr_501, target_6)
and func_7(vcinfo_495, target_7)
and func_9(vcinfo_495, vdest_mgr_501, target_9)
and func_11(vcinfo_495, target_11)
and vcinfo_495.getType().hasName("jpeg_decompress_struct")
and vdest_mgr_501.getType().hasName("djpeg_dest_ptr")
and vrequested_fmt.getType().hasName("IMAGE_FORMATS")
and vcinfo_495.getParentScope+() = func
and vdest_mgr_501.getParentScope+() = func
and not vrequested_fmt.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
