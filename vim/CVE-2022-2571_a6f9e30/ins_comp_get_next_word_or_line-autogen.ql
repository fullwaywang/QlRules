/**
 * @name vim-a6f9e300161f4cb54713da22f65b261595e8e614-ins_comp_get_next_word_or_line
 * @id cpp/vim/a6f9e300161f4cb54713da22f65b261595e8e614/ins-comp-get-next-word-or-line
 * @description vim-a6f9e300161f4cb54713da22f65b261595e8e614-src/insexpand.c-ins_comp_get_next_word_or_line CVE-2022-2571
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtmp_ptr_3502, BlockStmt target_2, ExprStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof FunctionCall
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_ptr_3502
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Function func, FunctionCall target_1) {
		target_1.getTarget().hasName("compl_status_adding")
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vtmp_ptr_3502, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vtmp_ptr_3502
		and target_2.getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("vim_iswordp")
		and target_2.getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_ptr_3502
		and target_2.getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_ptr_3502
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("find_word_start")
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_ptr_3502
}

predicate func_3(Variable vtmp_ptr_3502, ExprStmt target_3) {
		target_3.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vtmp_ptr_3502
}

from Function func, Variable vtmp_ptr_3502, FunctionCall target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vtmp_ptr_3502, target_2, target_3)
and func_1(func, target_1)
and func_2(vtmp_ptr_3502, target_2)
and func_3(vtmp_ptr_3502, target_3)
and vtmp_ptr_3502.getType().hasName("char_u *")
and vtmp_ptr_3502.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
