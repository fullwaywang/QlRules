/**
 * @name vim-05b27615481e72e3b338bb12990fb3e0c2ecc2a9-win_exchange
 * @id cpp/vim/05b27615481e72e3b338bb12990fb3e0c2ecc2a9/win-exchange
 * @description vim-05b27615481e72e3b338bb12990fb3e0c2ecc2a9-src/window.c-win_exchange CVE-2022-0319
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurwin, Variable vwp_1617, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_1617
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("buf_T *")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("reset_VIsual_and_resel")
		and target_0.getElse().(IfStmt).getCondition().(VariableAccess).getType().hasName("int")
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_1617
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcurwin, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("frame_fix_width")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcurwin
}

predicate func_2(Variable vwp_1617, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("frame_fix_width")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_1617
}

predicate func_3(Variable vwp_1617, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("win_enter")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_1617
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

from Function func, Variable vcurwin, Variable vwp_1617, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vcurwin, vwp_1617, target_1, target_2, target_3, func)
and func_1(vcurwin, target_1)
and func_2(vwp_1617, target_2)
and func_3(vwp_1617, target_3)
and vcurwin.getType().hasName("win_T *")
and vwp_1617.getType().hasName("win_T *")
and not vcurwin.getParentScope+() = func
and vwp_1617.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
