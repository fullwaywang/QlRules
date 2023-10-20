/**
 * @name libjpeg-turbo-073b0e88a192adebbb479ee2456beb089d8b5de7-main
 * @id cpp/libjpeg-turbo/073b0e88a192adebbb479ee2456beb089d8b5de7/main
 * @description libjpeg-turbo-073b0e88a192adebbb479ee2456beb089d8b5de7-djpeg.c-main CVE-2017-15232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrequested_fmt, Variable vcinfo_494, VariableAccess target_1, SwitchStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrequested_fmt
		and target_0.getThen().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="msg_code"
		and target_0.getThen().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="err"
		and target_0.getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="error_exit"
		and target_0.getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="err"
		and target_0.getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(ExprCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcinfo_494
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(ExprCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcrop, VariableAccess target_1) {
		target_1.getTarget()=vcrop
}

predicate func_2(Variable vrequested_fmt, Variable vcinfo_494, SwitchStmt target_2) {
		target_2.getExpr().(VariableAccess).getTarget()=vrequested_fmt
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jinit_write_bmp")
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcinfo_494
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_2.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jinit_write_bmp")
		and target_2.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcinfo_494
		and target_2.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

predicate func_3(Variable vcinfo_494, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_width"
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="output_width"
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_494
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="out_color_components"
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_494
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
}

from Function func, Variable vrequested_fmt, Variable vcrop, Variable vcinfo_494, VariableAccess target_1, SwitchStmt target_2, ExprStmt target_3
where
not func_0(vrequested_fmt, vcinfo_494, target_1, target_2, target_3)
and func_1(vcrop, target_1)
and func_2(vrequested_fmt, vcinfo_494, target_2)
and func_3(vcinfo_494, target_3)
and vrequested_fmt.getType().hasName("IMAGE_FORMATS")
and vcrop.getType().hasName("boolean")
and vcinfo_494.getType().hasName("jpeg_decompress_struct")
and not vrequested_fmt.getParentScope+() = func
and not vcrop.getParentScope+() = func
and vcinfo_494.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
