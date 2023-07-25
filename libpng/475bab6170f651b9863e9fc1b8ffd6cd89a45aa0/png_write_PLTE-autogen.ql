/**
 * @name libpng-475bab6170f651b9863e9fc1b8ffd6cd89a45aa0-png_write_PLTE
 * @id cpp/libpng/475bab6170f651b9863e9fc1b8ffd6cd89a45aa0/png-write-PLTE
 * @description libpng-475bab6170f651b9863e9fc1b8ffd6cd89a45aa0-pngwutil.c-png_write_PLTE CVE-2015-8126
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vpng_ptr_573, LogicalOrExpr target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("png_uint_32")
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_573
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="3"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_573
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vpng_ptr_573, LogicalOrExpr target_4) {
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mng_features_permitted"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_573
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
}

from Function func, Parameter vpng_ptr_573, LogicalOrExpr target_4
where
not func_1(vpng_ptr_573, target_4, func)
and func_4(vpng_ptr_573, target_4)
and vpng_ptr_573.getType().hasName("png_structp")
and vpng_ptr_573.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
