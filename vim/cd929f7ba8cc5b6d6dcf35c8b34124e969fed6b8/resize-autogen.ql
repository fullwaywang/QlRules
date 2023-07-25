/**
 * @name vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-resize
 * @id cpp/vim/cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8/resize
 * @description vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-src/libvterm/src/termscreen.c-resize CVE-2018-20786
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vscreen_482, PointerFieldAccess target_2, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("vterm_allocator_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vt"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_482
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sb_buffer"
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_482
		and target_0.getParent().(IfStmt).getCondition()=target_2
}

predicate func_1(Variable vscreen_482, Function func, IfStmt target_1) {
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="sb_buffer"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_482
		and target_1.getThen() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vscreen_482, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="sb_buffer"
		and target_2.getQualifier().(VariableAccess).getTarget()=vscreen_482
}

from Function func, Variable vscreen_482, ExprStmt target_0, IfStmt target_1, PointerFieldAccess target_2
where
func_0(vscreen_482, target_2, target_0)
and func_1(vscreen_482, func, target_1)
and func_2(vscreen_482, target_2)
and vscreen_482.getType().hasName("VTermScreen *")
and vscreen_482.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
