/**
 * @name vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-screen_new
 * @id cpp/vim/cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8/screen-new
 * @description vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-src/libvterm/src/termscreen.c-screen_new CVE-2018-20786
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstate_624, ReturnStmt target_5, ExprStmt target_6) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vstate_624
		and target_0.getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vscreen_625, ExprStmt target_7, ExprStmt target_8, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vscreen_625
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vscreen_625, ExprStmt target_9, ExprStmt target_10, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_625
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sb_buffer"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_625
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vterm_screen_free")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vscreen_625
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_2)
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vstate_624, ReturnStmt target_5, VariableAccess target_3) {
		target_3.getTarget()=vstate_624
		and target_3.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Variable vstate_624, ReturnStmt target_5, NotExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vstate_624
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="0"
}

predicate func_6(Variable vscreen_625, Variable vstate_624, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_625
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_624
}

predicate func_7(Variable vscreen_625, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vscreen_625
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vterm_allocator_malloc")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="136"
}

predicate func_8(Variable vscreen_625, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vt"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_625
}

predicate func_9(Variable vscreen_625, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sb_buffer"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_625
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vterm_allocator_malloc")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vt"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_625
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="40"
}

predicate func_10(Variable vscreen_625, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("vterm_state_set_callbacks")
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="state"
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscreen_625
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vscreen_625
}

from Function func, Variable vscreen_625, Variable vstate_624, VariableAccess target_3, NotExpr target_4, ReturnStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10
where
not func_0(vstate_624, target_5, target_6)
and not func_1(vscreen_625, target_7, target_8, func)
and not func_2(vscreen_625, target_9, target_10, func)
and func_3(vstate_624, target_5, target_3)
and func_4(vstate_624, target_5, target_4)
and func_5(target_5)
and func_6(vscreen_625, vstate_624, target_6)
and func_7(vscreen_625, target_7)
and func_8(vscreen_625, target_8)
and func_9(vscreen_625, target_9)
and func_10(vscreen_625, target_10)
and vscreen_625.getType().hasName("VTermScreen *")
and vstate_624.getType().hasName("VTermState *")
and vscreen_625.getParentScope+() = func
and vstate_624.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
