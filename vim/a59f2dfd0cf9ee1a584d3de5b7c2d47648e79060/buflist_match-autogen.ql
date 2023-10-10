/**
 * @name vim-a59f2dfd0cf9ee1a584d3de5b7c2d47648e79060-buflist_match
 * @id cpp/vim/a59f2dfd0cf9ee1a584d3de5b7c2d47648e79060/buflist-match
 * @description vim-a59f2dfd0cf9ee1a584d3de5b7c2d47648e79060-src/buffer.c-buflist_match CVE-2022-1674
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrmp_2927, ExprStmt target_2, ExprStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="regprog"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrmp_2927
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmatch_2931, ExprStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vmatch_2931
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vmatch_2931, Parameter vrmp_2927, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_2931
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fname_match")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrmp_2927
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="b_ffname"
}

predicate func_3(Variable vmatch_2931, Parameter vrmp_2927, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_2931
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fname_match")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrmp_2927
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="b_sfname"
}

from Function func, Variable vmatch_2931, Parameter vrmp_2927, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vrmp_2927, target_2, target_3)
and func_1(vmatch_2931, target_2, target_1)
and func_2(vmatch_2931, vrmp_2927, target_2)
and func_3(vmatch_2931, vrmp_2927, target_3)
and vmatch_2931.getType().hasName("char_u *")
and vrmp_2927.getType().hasName("regmatch_T *")
and vmatch_2931.getParentScope+() = func
and vrmp_2927.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
