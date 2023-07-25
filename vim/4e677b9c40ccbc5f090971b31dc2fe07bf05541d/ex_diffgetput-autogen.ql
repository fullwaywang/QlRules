/**
 * @name vim-4e677b9c40ccbc5f090971b31dc2fe07bf05541d-ex_diffgetput
 * @id cpp/vim/4e677b9c40ccbc5f090971b31dc2fe07bf05541d/ex-diffgetput
 * @description vim-4e677b9c40ccbc5f090971b31dc2fe07bf05541d-src/diff.c-ex_diffgetput CVE-2022-2598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vlnum_2666, FunctionCall target_1) {
		target_1.getTarget().hasName("ml_delete")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vlnum_2666
}

predicate func_2(Variable vadded_2677, ExprStmt target_2) {
		target_2.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vadded_2677
}

predicate func_3(Function func, ExprStmt target_3) {
		target_3.getExpr() instanceof FunctionCall
		and target_3.getEnclosingFunction() = func
}

from Function func, Variable vlnum_2666, Variable vadded_2677, FunctionCall target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(func)
and func_1(vlnum_2666, target_1)
and func_2(vadded_2677, target_2)
and func_3(func, target_3)
and vlnum_2666.getType().hasName("linenr_T")
and vadded_2677.getType().hasName("int")
and vlnum_2666.getParentScope+() = func
and vadded_2677.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
