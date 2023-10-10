/**
 * @name vim-4e889f98e95ac05d7c8bd3ee933ab4d47820fdfa-change_indent
 * @id cpp/vim/4e889f98e95ac05d7c8bd3ee933ab4d47820fdfa/change-indent
 * @description vim-4e889f98e95ac05d7c8bd3ee933ab4d47820fdfa-src/indent.c-change_indent CVE-2022-0714
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_cursor_col_1250, Variable vptr_1252, ExprStmt target_1, PointerArithmeticOperation target_2, PointerArithmeticOperation target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_1252
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vnew_cursor_col_1250
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BreakStmt).toString() = "break;"
		and target_1.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vnew_cursor_col_1250, ExprStmt target_1) {
		target_1.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vnew_cursor_col_1250
}

predicate func_2(Variable vnew_cursor_col_1250, Variable vptr_1252, PointerArithmeticOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vptr_1252
		and target_2.getAnOperand().(VariableAccess).getTarget()=vnew_cursor_col_1250
}

predicate func_3(Variable vnew_cursor_col_1250, Variable vptr_1252, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vptr_1252
		and target_3.getAnOperand().(VariableAccess).getTarget()=vnew_cursor_col_1250
}

predicate func_4(Variable vnew_cursor_col_1250, Variable vptr_1252, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("lbr_chartabsize")
		and target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_1252
		and target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_1252
		and target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vnew_cursor_col_1250
}

from Function func, Variable vnew_cursor_col_1250, Variable vptr_1252, ExprStmt target_1, PointerArithmeticOperation target_2, PointerArithmeticOperation target_3, ExprStmt target_4
where
not func_0(vnew_cursor_col_1250, vptr_1252, target_1, target_2, target_3, target_4)
and func_1(vnew_cursor_col_1250, target_1)
and func_2(vnew_cursor_col_1250, vptr_1252, target_2)
and func_3(vnew_cursor_col_1250, vptr_1252, target_3)
and func_4(vnew_cursor_col_1250, vptr_1252, target_4)
and vnew_cursor_col_1250.getType().hasName("int")
and vptr_1252.getType().hasName("char_u *")
and vnew_cursor_col_1250.getParentScope+() = func
and vptr_1252.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
