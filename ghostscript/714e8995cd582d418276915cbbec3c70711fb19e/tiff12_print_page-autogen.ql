/**
 * @name ghostscript-714e8995cd582d418276915cbbec3c70711fb19e-tiff12_print_page
 * @id cpp/ghostscript/714e8995cd582d418276915cbbec3c70711fb19e/tiff12-print-page
 * @description ghostscript-714e8995cd582d418276915cbbec3c70711fb19e-devices/gdevtfnx.c-tiff12_print_page CVE-2020-16300
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_148, VariableAccess target_0) {
		target_0.getTarget()=vsize_148
		and target_0.getParent().(ExprCall).getParent().(Initializer).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_0.getParent().(ExprCall).getParent().(Initializer).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_0.getParent().(ExprCall).getParent().(Initializer).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_0.getParent().(ExprCall).getParent().(Initializer).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
		and target_0.getParent().(ExprCall).getParent().(Initializer).getExpr().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_0.getParent().(ExprCall).getParent().(Initializer).getExpr().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gx_device_printer *")
		and target_0.getParent().(ExprCall).getParent().(Initializer).getExpr().(ExprCall).getArgument(2).(StringLiteral).getValue()="tiff12_print_page"
}

predicate func_1(Variable vsize_148, VariableAccess target_1) {
		target_1.getTarget()=vsize_148
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("byte *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Variable vsize_148, VariableAccess target_0, VariableAccess target_1
where
func_0(vsize_148, target_0)
and func_1(vsize_148, target_1)
and vsize_148.getType().hasName("int")
and vsize_148.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
