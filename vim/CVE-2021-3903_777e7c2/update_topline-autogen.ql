/**
 * @name vim-777e7c21b7627be80961848ac560cb0a9978ff43-update_topline
 * @id cpp/vim/777e7c21b7627be80961848ac560cb0a9978ff43/update-topline
 * @description vim-777e7c21b7627be80961848ac560cb0a9978ff43-src/move.c-update_topline CVE-2021-3903
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurwin, LogicalOrExpr target_1, ExprStmt target_0) {
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w_valid"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_0.getExpr().(AssignOrExpr).getRValue().(BitwiseOrExpr).getValue()="96"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
}

predicate func_1(Variable vcurwin, LogicalOrExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("screen_valid")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_height"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vcurwin, ExprStmt target_0, LogicalOrExpr target_1
where
func_0(vcurwin, target_1, target_0)
and func_1(vcurwin, target_1)
and vcurwin.getType().hasName("win_T *")
and not vcurwin.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
