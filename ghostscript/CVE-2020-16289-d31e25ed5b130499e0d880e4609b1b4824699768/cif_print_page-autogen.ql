/**
 * @name ghostscript-d31e25ed5b130499e0d880e4609b1b4824699768-cif_print_page
 * @id cpp/ghostscript/d31e25ed5b130499e0d880e4609b1b4824699768/cif-print-page
 * @description ghostscript-d31e25ed5b130499e0d880e4609b1b4824699768-devices/gdevcif.c-cif_print_page CVE-2020-16289
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_51, ExprStmt target_2, ExprStmt target_3) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vlength_51
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_byte_array"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vlength_51
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(2).(SizeofTypeOperator).getValue()="1"
		and target_0.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(3).(StringLiteral).getValue()="cif_print_page(s)"
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vlength_51, VariableAccess target_1) {
		target_1.getTarget()=vlength_51
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_byte_array"
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(2).(SizeofTypeOperator).getValue()="1"
		and target_1.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(3).(StringLiteral).getValue()="cif_print_page(s)"
}

predicate func_2(Variable vlength_51, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_51
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="fname"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
}

predicate func_3(Variable vlength_51, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fname"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_51
}

from Function func, Variable vlength_51, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vlength_51, target_2, target_3)
and func_1(vlength_51, target_1)
and func_2(vlength_51, target_2)
and func_3(vlength_51, target_3)
and vlength_51.getType().hasName("int")
and vlength_51.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
