/**
 * @name vim-cd38bb4d83c942c4bad596835c6766cbf32e5195-diff_redraw
 * @id cpp/vim/cd38bb4d83c942c4bad596835c6766cbf32e5195/diff-redraw
 * @description vim-cd38bb4d83c942c4bad596835c6766cbf32e5195-src/diff.c-diff_redraw CVE-2022-2208
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwp_665, BlockStmt target_2, AssignExpr target_3, ValueFieldAccess target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof ValueFieldAccess
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("buf_valid")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="w_buffer"
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_665
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vwp_665, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="wo_diff"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="w_onebuf_opt"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_665
}

predicate func_2(Variable vwp_665, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("redraw_win_later")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_665
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="35"
		and target_2.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vwp_665
		and target_2.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vwp_665
}

predicate func_3(Variable vwp_665, AssignExpr target_3) {
		target_3.getLValue().(VariableAccess).getTarget()=vwp_665
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="w_next"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwp_665
}

from Function func, Variable vwp_665, ValueFieldAccess target_1, BlockStmt target_2, AssignExpr target_3
where
not func_0(vwp_665, target_2, target_3, target_1)
and func_1(vwp_665, target_1)
and func_2(vwp_665, target_2)
and func_3(vwp_665, target_3)
and vwp_665.getType().hasName("win_T *")
and vwp_665.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
