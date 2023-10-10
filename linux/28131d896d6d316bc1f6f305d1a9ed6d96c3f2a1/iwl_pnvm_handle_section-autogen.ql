/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pnvm_handle_section
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-pnvm-handle-section
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pnvm_handle_section CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="loaded PNVM version 0x%0x\n"
		and not target_0.getValue()="loaded PNVM version %08x\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(SubExpr target_3 |
		target_3.getValue()="25"
		and target_3.getLeftOperand().(SizeofExprOperator).getValue()="27"
		and target_3.getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="loaded PNVM version 0x%0x\n"
		and target_3.getRightOperand().(Literal).getValue()="2"
		and target_3.getParent().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="loaded PNVM version 0x%0x\n"
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(StringLiteral target_5 |
		target_5.getValue()="loaded PNVM version %08x\n"
		and target_5.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_3(func)
and not func_5(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
