/**
 * @name libpng-61a2d8a2a7b03023e63eae9a3e64607aaaa6d339-png_handle_sCAL
 * @id cpp/libpng/61a2d8a2a7b03023e63eae9a3e64607aaaa6d339/png-handle-sCAL
 * @description libpng-61a2d8a2a7b03023e63eae9a3e64607aaaa6d339-pngrutil.c-png_handle_sCAL CVE-2011-2692
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_1834, Parameter vlength_1834, BitwiseAndExpr target_3, ExprStmt target_4, ExprStmt target_5, AddExpr target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_1834
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_warning")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="sCAL chunk too short"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_crc_finish")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_1834
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getElse().(IfStmt).getElse()=target_0
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Function func, ReturnStmt target_2) {
		target_2.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vpng_ptr_1834, BitwiseAndExpr target_3) {
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1834
		and target_3.getRightOperand().(Literal).getValue()="4"
}

predicate func_4(Parameter vpng_ptr_1834, Parameter vlength_1834, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("png_crc_finish")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_1834
}

predicate func_5(Parameter vpng_ptr_1834, Parameter vlength_1834, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1834
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("png_malloc_warn")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1834
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlength_1834
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_6(Parameter vlength_1834, AddExpr target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vlength_1834
		and target_6.getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vpng_ptr_1834, Parameter vlength_1834, ReturnStmt target_2, BitwiseAndExpr target_3, ExprStmt target_4, ExprStmt target_5, AddExpr target_6
where
not func_0(vpng_ptr_1834, vlength_1834, target_3, target_4, target_5, target_6)
and func_2(func, target_2)
and func_3(vpng_ptr_1834, target_3)
and func_4(vpng_ptr_1834, vlength_1834, target_4)
and func_5(vpng_ptr_1834, vlength_1834, target_5)
and func_6(vlength_1834, target_6)
and vpng_ptr_1834.getType().hasName("png_structp")
and vlength_1834.getType().hasName("png_uint_32")
and vpng_ptr_1834.getParentScope+() = func
and vlength_1834.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
