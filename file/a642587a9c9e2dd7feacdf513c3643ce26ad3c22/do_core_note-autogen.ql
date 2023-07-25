/**
 * @name file-a642587a9c9e2dd7feacdf513c3643ce26ad3c22-do_core_note
 * @id cpp/file/a642587a9c9e2dd7feacdf513c3643ce26ad3c22/do-core-note
 * @description file-a642587a9c9e2dd7feacdf513c3643ce26ad3c22-src/readelf.c-do_core_note CVE-2018-10360
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcp_776, Parameter vsize_695, Parameter vnbuf_693, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_4, RelationalOperation target_5, ExprStmt target_6) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcp_776
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnbuf_693
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_695
		and target_0.getAnOperand() instanceof PointerDereferenceExpr
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcp_776
		and target_0.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcp_776, BlockStmt target_2, PointerDereferenceExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vcp_776
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcp_776
		and target_1.getParent().(LogicalAndExpr).getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ContinueStmt).toString() = "continue;"
		and target_2.getStmt(1).(LabelStmt).toString() = "label ...:"
}

predicate func_3(Variable vcp_776, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcp_776
}

predicate func_4(Variable vcp_776, LogicalAndExpr target_4) {
		target_4.getAnOperand() instanceof PointerDereferenceExpr
		and target_4.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_4.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcp_776
}

predicate func_5(Parameter vsize_695, RelationalOperation target_5) {
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vsize_695
}

predicate func_6(Parameter vnbuf_693, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnbuf_693
}

from Function func, Variable vcp_776, Parameter vsize_695, Parameter vnbuf_693, PointerDereferenceExpr target_1, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_4, RelationalOperation target_5, ExprStmt target_6
where
not func_0(vcp_776, vsize_695, vnbuf_693, target_2, target_3, target_4, target_5, target_6)
and func_1(vcp_776, target_2, target_1)
and func_2(target_2)
and func_3(vcp_776, target_3)
and func_4(vcp_776, target_4)
and func_5(vsize_695, target_5)
and func_6(vnbuf_693, target_6)
and vcp_776.getType().hasName("unsigned char *")
and vsize_695.getType().hasName("size_t")
and vnbuf_693.getType().hasName("unsigned char *")
and vcp_776.getParentScope+() = func
and vsize_695.getParentScope+() = func
and vnbuf_693.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
