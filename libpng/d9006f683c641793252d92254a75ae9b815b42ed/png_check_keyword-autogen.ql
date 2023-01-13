/**
 * @name libpng-d9006f683c641793252d92254a75ae9b815b42ed-png_check_keyword
 * @id cpp/libpng/d9006f683c641793252d92254a75ae9b815b42ed/png-check-keyword
 * @description libpng-d9006f683c641793252d92254a75ae9b815b42ed-png_check_keyword CVE-2015-8540
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vkey_len_1530) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vkey_len_1530
		and target_0.getAnOperand() instanceof EqualityOperation)
}

predicate func_1(Variable vkp_1532) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vkp_1532
		and target_1.getAnOperand().(CharLiteral).getValue()="32")
}

predicate func_2(Parameter vnew_key_1528, Variable vkey_len_1530, Variable vkp_1532) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vkp_1532
		and target_2.getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnew_key_1528
		and target_2.getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vkey_len_1530
		and target_2.getRValue().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1")
}

from Function func, Parameter vnew_key_1528, Variable vkey_len_1530, Variable vkp_1532
where
not func_0(vkey_len_1530)
and func_1(vkp_1532)
and vkey_len_1530.getType().hasName("png_size_t")
and func_2(vnew_key_1528, vkey_len_1530, vkp_1532)
and vkp_1532.getType().hasName("png_charp")
and vnew_key_1528.getParentScope+() = func
and vkey_len_1530.getParentScope+() = func
and vkp_1532.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
