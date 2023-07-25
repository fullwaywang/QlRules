/**
 * @name libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-t2p_readwrite_pdf_image
 * @id cpp/libtiff/83a4b92815ea04969d494416eaae3d4c6b338e4a/t2p-readwrite-pdf-image
 * @description libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-tools/tiff2pdf.c-t2p_readwrite_pdf_image CVE-2016-9533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vt2p_2155, ExprStmt target_1, NotExpr target_2) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="tiff_datasize"
		and target_0.getQualifier().(VariableAccess).getTarget()=vt2p_2155
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vt2p_2155, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="t2p_error"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_2155
}

predicate func_2(Parameter vt2p_2155, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("t2p_process_jpeg_strip")
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_2.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_2.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_2.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_2.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("tstrip_t")
		and target_2.getOperand().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="tiff_length"
		and target_2.getOperand().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vt2p_2155
}

from Function func, Parameter vt2p_2155, ExprStmt target_1, NotExpr target_2
where
not func_0(vt2p_2155, target_1, target_2)
and func_1(vt2p_2155, target_1)
and func_2(vt2p_2155, target_2)
and vt2p_2155.getType().hasName("T2P *")
and vt2p_2155.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
