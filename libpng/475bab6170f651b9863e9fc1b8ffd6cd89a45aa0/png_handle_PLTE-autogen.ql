/**
 * @name libpng-475bab6170f651b9863e9fc1b8ffd6cd89a45aa0-png_handle_PLTE
 * @id cpp/libpng/475bab6170f651b9863e9fc1b8ffd6cd89a45aa0/png-handle-PLTE
 * @description libpng-475bab6170f651b9863e9fc1b8ffd6cd89a45aa0-pngrutil.c-png_handle_PLTE CVE-2015-8126
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vpng_ptr_506, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_506
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="3"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_506
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="256"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vnum_509, ExprStmt target_5, RelationalOperation target_6, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnum_509
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_509
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_2)
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vpng_ptr_506, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("png_error")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_506
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid palette chunk"
}

predicate func_4(Parameter vpng_ptr_506, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("png_crc_read")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_506
		and target_4.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="3"
}

predicate func_5(Variable vnum_509, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_509
		and target_5.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="3"
}

predicate func_6(Variable vnum_509, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vnum_509
}

from Function func, Variable vnum_509, Parameter vpng_ptr_506, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6
where
not func_1(vpng_ptr_506, target_3, target_4, func)
and not func_2(vnum_509, target_5, target_6, func)
and func_3(vpng_ptr_506, target_3)
and func_4(vpng_ptr_506, target_4)
and func_5(vnum_509, target_5)
and func_6(vnum_509, target_6)
and vnum_509.getType().hasName("int")
and vpng_ptr_506.getType().hasName("png_structp")
and vnum_509.getParentScope+() = func
and vpng_ptr_506.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
