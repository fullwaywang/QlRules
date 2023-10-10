/**
 * @name vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-create_pty_only
 * @id cpp/vim/cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8/create-pty-only
 * @description vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-src/terminal.c-create_pty_only CVE-2018-20786
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vterm_5845, FunctionCall target_1) {
		target_1.getTarget().hasName("create_vterm")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vterm_5845
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="tl_rows"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vterm_5845
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="tl_cols"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vterm_5845
}

predicate func_2(Function func, ExprStmt target_2) {
		target_2.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Parameter vterm_5845, FunctionCall target_1, ExprStmt target_2
where
not func_0(func)
and func_1(vterm_5845, target_1)
and func_2(func, target_2)
and vterm_5845.getType().hasName("term_T *")
and vterm_5845.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
