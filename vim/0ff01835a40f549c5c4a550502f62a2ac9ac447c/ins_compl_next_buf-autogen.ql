/**
 * @name vim-0ff01835a40f549c5c4a550502f62a2ac9ac447c-ins_compl_next_buf
 * @id cpp/vim/0ff01835a40f549c5c4a550502f62a2ac9ac447c/ins-compl-next-buf
 * @description vim-0ff01835a40f549c5c4a550502f62a2ac9ac447c-src/insexpand.c-ins_compl_next_buf CVE-2022-3297
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwp_2489, ExprStmt target_3) {
	exists(NotExpr target_0 |
		target_0.getOperand().(FunctionCall).getTarget().hasName("win_valid")
		and target_0.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_2489
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3)
}

predicate func_1(Variable vwp_2489, VariableAccess target_1) {
		target_1.getTarget()=vwp_2489
}

predicate func_2(Variable vwp_2489, ExprStmt target_3, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vwp_2489
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(Variable vwp_2489, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwp_2489
}

from Function func, Variable vwp_2489, VariableAccess target_1, EqualityOperation target_2, ExprStmt target_3
where
not func_0(vwp_2489, target_3)
and func_1(vwp_2489, target_1)
and func_2(vwp_2489, target_3, target_2)
and func_3(vwp_2489, target_3)
and vwp_2489.getType().hasName("win_T *")
and vwp_2489.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
