/**
 * @name vim-80525751c5ce9ed82c41d83faf9ef38667bf61b1-do_mouse
 * @id cpp/vim/80525751c5ce9ed82c41d83faf9ef38667bf61b1/do-mouse
 * @description vim-80525751c5ce9ed82c41d83faf9ef38667bf61b1-src/mouse.c-do_mouse CVE-2022-2980
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("short *")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(36)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(36).getFollowingStmt()=target_0))
}

predicate func_1(Variable vis_click_230, Variable vis_drag_231, Variable vin_tab_line_236, Variable vc1_238, Variable vmouse_row, Variable vmouse_col, Variable vTabPageIdxs, Variable vfirstwin, Variable vcmdwin_type, Variable vColumns, Function func, IfStmt target_1) {
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmouse_row
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="w_winrow"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfirstwin
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vis_drag_231
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vin_tab_line_236
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_click_230
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmdwin_type
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmouse_col
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vColumns
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vin_tab_line_236
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc1_238
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vc1_238
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_drag_231
		and target_1.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vin_tab_line_236
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc1_238
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vTabPageIdxs
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vmouse_col
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("tabpage_move")
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(Literal).getValue()="9999"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Variable vis_click_230, Variable vis_drag_231, Variable vin_tab_line_236, Variable vc1_238, Variable vmouse_row, Variable vmouse_col, Variable vTabPageIdxs, Variable vfirstwin, Variable vcmdwin_type, Variable vColumns, IfStmt target_1
where
not func_0(func)
and func_1(vis_click_230, vis_drag_231, vin_tab_line_236, vc1_238, vmouse_row, vmouse_col, vTabPageIdxs, vfirstwin, vcmdwin_type, vColumns, func, target_1)
and vis_click_230.getType().hasName("int")
and vis_drag_231.getType().hasName("int")
and vin_tab_line_236.getType().hasName("int")
and vc1_238.getType().hasName("int")
and vmouse_row.getType().hasName("int")
and vmouse_col.getType().hasName("int")
and vTabPageIdxs.getType().hasName("short *")
and vfirstwin.getType().hasName("win_T *")
and vcmdwin_type.getType().hasName("int")
and vColumns.getType().hasName("long")
and vis_click_230.getParentScope+() = func
and vis_drag_231.getParentScope+() = func
and vin_tab_line_236.getParentScope+() = func
and vc1_238.getParentScope+() = func
and not vmouse_row.getParentScope+() = func
and not vmouse_col.getParentScope+() = func
and not vTabPageIdxs.getParentScope+() = func
and not vfirstwin.getParentScope+() = func
and not vcmdwin_type.getParentScope+() = func
and not vColumns.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
