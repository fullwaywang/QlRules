/**
 * @name vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-vterm_obtain_state
 * @id cpp/vim/cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8/vterm-obtain-state
 * @description vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-src/libvterm/src/state.c-vterm_obtain_state CVE-2018-20786
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstate_1698, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstate_1698
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstate_1698, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_1698
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vterm_state_new")
}

predicate func_2(Variable vstate_1698, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_1698
}

from Function func, Variable vstate_1698, ExprStmt target_1, ExprStmt target_2
where
not func_0(vstate_1698, target_1, target_2, func)
and func_1(vstate_1698, target_1)
and func_2(vstate_1698, target_2)
and vstate_1698.getType().hasName("VTermState *")
and vstate_1698.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
