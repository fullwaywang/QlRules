/**
 * @name libpng-61a2d8a2a7b03023e63eae9a3e64607aaaa6d339-png_handle_sCAL
 * @id cpp/libpng/61a2d8a2a7b03023e63eae9a3e64607aaaa6d339/png-handle-sCAL
 * @description libpng-61a2d8a2a7b03023e63eae9a3e64607aaaa6d339-png_handle_sCAL CVE-2011-2692
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_1834, Parameter vlength_1834) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_1834
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_warning")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_crc_finish")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_1834
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1834
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_5(Parameter vpng_ptr_1834, Parameter vlength_1834) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("png_crc_finish")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_5.getArgument(1).(VariableAccess).getTarget()=vlength_1834)
}

predicate func_6(Parameter vpng_ptr_1834, Parameter vlength_1834) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_6.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1834
		and target_6.getRValue().(FunctionCall).getTarget().hasName("png_malloc_warn")
		and target_6.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_6.getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlength_1834
		and target_6.getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1")
}

from Function func, Parameter vpng_ptr_1834, Parameter vlength_1834
where
not func_0(vpng_ptr_1834, vlength_1834)
and vpng_ptr_1834.getType().hasName("png_structp")
and func_5(vpng_ptr_1834, vlength_1834)
and func_6(vpng_ptr_1834, vlength_1834)
and vlength_1834.getType().hasName("png_uint_32")
and vpng_ptr_1834.getParentScope+() = func
and vlength_1834.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
