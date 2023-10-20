/**
 * @name vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-realloc_buffer
 * @id cpp/vim/cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8/realloc-buffer
 * @description vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-src/libvterm/src/termscreen.c-realloc_buffer CVE-2018-20786
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuffer_80, Parameter vscreen_80, VariableAccess target_2, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("vterm_allocator_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vt"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_80
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_80
		and target_0.getParent().(IfStmt).getCondition()=target_2
}

predicate func_1(Parameter vbuffer_80, Function func, IfStmt target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vbuffer_80
		and target_1.getThen() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vbuffer_80, VariableAccess target_2) {
		target_2.getTarget()=vbuffer_80
}

from Function func, Parameter vbuffer_80, Parameter vscreen_80, ExprStmt target_0, IfStmt target_1, VariableAccess target_2
where
func_0(vbuffer_80, vscreen_80, target_2, target_0)
and func_1(vbuffer_80, func, target_1)
and func_2(vbuffer_80, target_2)
and vbuffer_80.getType().hasName("ScreenCell *")
and vscreen_80.getType().hasName("VTermScreen *")
and vbuffer_80.getParentScope+() = func
and vscreen_80.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
