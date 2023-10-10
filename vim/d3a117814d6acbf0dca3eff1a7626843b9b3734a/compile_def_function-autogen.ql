/**
 * @name vim-d3a117814d6acbf0dca3eff1a7626843b9b3734a-compile_def_function
 * @id cpp/vim/d3a117814d6acbf0dca3eff1a7626843b9b3734a/compile-def-function
 * @description vim-d3a117814d6acbf0dca3eff1a7626843b9b3734a-src/vim9compile.c-compile_def_function CVE-2022-0128
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcmd_2617, LogicalAndExpr target_2) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcmd_2617
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcmd_2617, EqualityOperation target_1) {
		target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcmd_2617
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcmd_2617
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_2(Variable vcmd_2617, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcmd_2617
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="36"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcmd_2617
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="39"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
}

from Function func, Variable vcmd_2617, EqualityOperation target_1, LogicalAndExpr target_2
where
not func_0(vcmd_2617, target_2)
and func_1(vcmd_2617, target_1)
and func_2(vcmd_2617, target_2)
and vcmd_2617.getType().hasName("char_u *")
and vcmd_2617.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
