/**
 * @name vim-0f6e28f686dbb59ab3b562408ab9b2234797b9b1-get_user_var_name
 * @id cpp/vim/0f6e28f686dbb59ab3b562408ab9b2234797b9b1/get-user-var-name
 * @description vim-0f6e28f686dbb59ab3b562408ab9b2234797b9b1-src/evalvars.c-get_user_var_name CVE-2022-0696
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

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("prevwin_curwin")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vprevwin, Variable vcurbuf, ConditionalExpr target_2) {
		target_2.getCondition().(FunctionCall).getTarget().hasName("is_in_cmdwin")
		and target_2.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dv_hashtab"
		and target_2.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_vars"
		and target_2.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_2.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprevwin
		and target_2.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dv_hashtab"
		and target_2.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_vars"
		and target_2.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_2.getParent().(AssignExpr).getRValue() = target_2
}

/*predicate func_3(Variable vprevwin, VariableAccess target_3) {
		target_3.getTarget()=vprevwin
}

*/
/*predicate func_4(Variable vcurbuf, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="b_vars"
		and target_4.getQualifier().(VariableAccess).getTarget()=vcurbuf
}

*/
predicate func_5(Variable vprevwin, Variable vcurwin, ConditionalExpr target_5) {
		target_5.getCondition().(FunctionCall).getTarget().hasName("is_in_cmdwin")
		and target_5.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dv_hashtab"
		and target_5.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_vars"
		and target_5.getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprevwin
		and target_5.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dv_hashtab"
		and target_5.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_vars"
		and target_5.getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_5.getParent().(AssignExpr).getRValue() = target_5
}

/*predicate func_6(Variable vprevwin, PointerFieldAccess target_8, VariableAccess target_6) {
		target_6.getTarget()=vprevwin
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getLocation())
}

*/
predicate func_8(Variable vprevwin, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="b_vars"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprevwin
}

from Function func, Variable vprevwin, Variable vcurbuf, Variable vcurwin, ConditionalExpr target_2, ConditionalExpr target_5, PointerFieldAccess target_8
where
not func_0(func)
and not func_1(func)
and func_2(vprevwin, vcurbuf, target_2)
and func_5(vprevwin, vcurwin, target_5)
and func_8(vprevwin, target_8)
and vprevwin.getType().hasName("win_T *")
and vcurbuf.getType().hasName("buf_T *")
and vcurwin.getType().hasName("win_T *")
and not vprevwin.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
and not vcurwin.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
