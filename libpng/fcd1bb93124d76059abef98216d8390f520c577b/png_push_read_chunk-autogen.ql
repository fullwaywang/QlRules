/**
 * @name libpng-fcd1bb93124d76059abef98216d8390f520c577b-png_push_read_chunk
 * @id cpp/libpng/fcd1bb93124d76059abef98216d8390f520c577b/png-push-read-chunk
 * @description libpng-fcd1bb93124d76059abef98216d8390f520c577b-pngpread.c-png_push_read_chunk CVE-2017-12652
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_167, ExprStmt target_1, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="chunk_name"
		and target_0.getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Parameter vpng_ptr_167, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("png_check_chunk_length")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="chunk_name"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="push_length"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_167
}

from Function func, Parameter vpng_ptr_167, PointerFieldAccess target_0, ExprStmt target_1
where
func_0(vpng_ptr_167, target_1, target_0)
and func_1(vpng_ptr_167, target_1)
and vpng_ptr_167.getType().hasName("png_structrp")
and vpng_ptr_167.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
