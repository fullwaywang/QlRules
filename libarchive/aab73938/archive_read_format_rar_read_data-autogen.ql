/**
 * @name libarchive-aab73938-archive_read_format_rar_read_data
 * @id cpp/libarchive/aab73938/archive-read-format-rar-read-data
 * @description libarchive-aab73938-libarchive/archive_read_support_format_rar.c-archive_read_format_rar_read_data CVE-2015-8926
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuff_989, LogicalOrExpr target_1, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbuff_989
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
}

predicate func_1(LogicalOrExpr target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="entry_eof"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="offset_seek"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="unp_size"
}

from Function func, Parameter vbuff_989, ExprStmt target_0, LogicalOrExpr target_1
where
func_0(vbuff_989, target_1, target_0)
and func_1(target_1)
and vbuff_989.getType().hasName("const void **")
and vbuff_989.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
