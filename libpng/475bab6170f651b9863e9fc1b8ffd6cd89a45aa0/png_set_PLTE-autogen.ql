/**
 * @name libpng-475bab6170f651b9863e9fc1b8ffd6cd89a45aa0-png_set_PLTE
 * @id cpp/libpng/475bab6170f651b9863e9fc1b8ffd6cd89a45aa0/png-set-PLTE
 * @description libpng-475bab6170f651b9863e9fc1b8ffd6cd89a45aa0-pngset.c-png_set_PLTE CVE-2015-8126
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_448, LogicalOrExpr target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("png_uint_32")
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_448
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="3"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_448
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vpng_ptr_448, LogicalOrExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpng_ptr_448
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vpng_ptr_448, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("png_error")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_448
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid palette length"
}

from Function func, Parameter vpng_ptr_448, LogicalOrExpr target_3, ExprStmt target_4
where
not func_0(vpng_ptr_448, target_3, target_4, func)
and func_3(vpng_ptr_448, target_3)
and func_4(vpng_ptr_448, target_4)
and vpng_ptr_448.getType().hasName("png_structp")
and vpng_ptr_448.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
