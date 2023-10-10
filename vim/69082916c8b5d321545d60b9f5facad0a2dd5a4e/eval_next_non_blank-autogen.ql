/**
 * @name vim-69082916c8b5d321545d60b9f5facad0a2dd5a4e-eval_next_non_blank
 * @id cpp/vim/69082916c8b5d321545d60b9f5facad0a2dd5a4e/eval-next-non-blank
 * @description vim-69082916c8b5d321545d60b9f5facad0a2dd5a4e-src/eval.c-eval_next_non_blank CVE-2022-3278
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="10"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vp_2273, ExprStmt target_2, ReturnStmt target_3) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2273
		and target_1.getAnOperand().(Literal).getValue()="10"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(VariableAccess).getLocation()))
}

predicate func_2(Variable vp_2273, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("newline_skip_comments")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2273
}

predicate func_3(Variable vp_2273, ReturnStmt target_3) {
		target_3.getExpr().(VariableAccess).getTarget()=vp_2273
}

from Function func, Variable vp_2273, Literal target_0, ExprStmt target_2, ReturnStmt target_3
where
func_0(func, target_0)
and not func_1(vp_2273, target_2, target_3)
and func_2(vp_2273, target_2)
and func_3(vp_2273, target_3)
and vp_2273.getType().hasName("char_u *")
and vp_2273.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
