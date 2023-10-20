/**
 * @name vim-ec66c41d84e574baf8009dbc0bd088d2bc5b2421-win_enter_ext
 * @id cpp/vim/ec66c41d84e574baf8009dbc0bd088d2bc5b2421/win-enter-ext
 * @description vim-ec66c41d84e574baf8009dbc0bd088d2bc5b2421-src/window.c-win_enter_ext CVE-2019-20079
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwp_4548, ExprStmt target_1, VariableAccess target_0) {
		target_0.getTarget()=vwp_4548
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Parameter vwp_4548, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_4548
}

from Function func, Parameter vwp_4548, VariableAccess target_0, ExprStmt target_1
where
func_0(vwp_4548, target_1, target_0)
and func_1(vwp_4548, target_1)
and vwp_4548.getType().hasName("win_T *")
and vwp_4548.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
