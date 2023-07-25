/**
 * @name libpng-216dbf7f7eef5d999f2e3ba054407917098e9f85-png_handle_PLTE
 * @id cpp/libpng/216dbf7f7eef5d999f2e3ba054407917098e9f85/png-handle-PLTE
 * @description libpng-216dbf7f7eef5d999f2e3ba054407917098e9f85-pngrutil.c-png_handle_PLTE CVE-2015-8126
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmax_palette_length_509, RelationalOperation target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof EqualityOperation
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_palette_length_509
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof BinaryBitwiseOperation
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_palette_length_509
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpng_ptr_506, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_506
		and target_1.getAnOperand().(BitwiseOrExpr).getValue()="3"
}

predicate func_2(Parameter vpng_ptr_506, BinaryBitwiseOperation target_2) {
		target_2.getLeftOperand().(Literal).getValue()="1"
		and target_2.getRightOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_2.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_506
}

predicate func_4(Variable vmax_palette_length_509, ConditionalExpr target_4) {
		target_4.getCondition() instanceof EqualityOperation
		and target_4.getThen() instanceof BinaryBitwiseOperation
		and target_4.getElse() instanceof Literal
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_palette_length_509
}

predicate func_5(Variable vmax_palette_length_509, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vmax_palette_length_509
}

from Function func, Variable vmax_palette_length_509, Parameter vpng_ptr_506, EqualityOperation target_1, BinaryBitwiseOperation target_2, ConditionalExpr target_4, RelationalOperation target_5
where
not func_0(vmax_palette_length_509, target_5, func)
and func_1(vpng_ptr_506, target_1)
and func_2(vpng_ptr_506, target_2)
and func_4(vmax_palette_length_509, target_4)
and func_5(vmax_palette_length_509, target_5)
and vmax_palette_length_509.getType().hasName("int")
and vpng_ptr_506.getType().hasName("png_structp")
and vmax_palette_length_509.getParentScope+() = func
and vpng_ptr_506.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
