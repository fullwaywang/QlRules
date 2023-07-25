/**
 * @name vim-0f6e28f686dbb59ab3b562408ab9b2234797b9b1-uc_list
 * @id cpp/vim/0f6e28f686dbb59ab3b562408ab9b2234797b9b1/uc-list
 * @description vim-0f6e28f686dbb59ab3b562408ab9b2234797b9b1-src/usercmd.c-uc_list CVE-2022-0696
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("prevwin_curwin")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vprevwin, Variable vcurbuf, ConditionalExpr target_1) {
		target_1.getCondition().(FunctionCall).getTarget().hasName("is_in_cmdwin")
		and target_1.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b_ucmds"
		and target_1.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_1.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprevwin
		and target_1.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b_ucmds"
		and target_1.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

/*predicate func_2(Variable vprevwin, VariableAccess target_2) {
		target_2.getTarget()=vprevwin
}

*/
from Function func, Variable vprevwin, Variable vcurbuf, ConditionalExpr target_1
where
not func_0(func)
and func_1(vprevwin, vcurbuf, target_1)
and vprevwin.getType().hasName("win_T *")
and vcurbuf.getType().hasName("buf_T *")
and not vprevwin.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
