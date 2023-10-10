/**
 * @name vim-4e677b9c40ccbc5f090971b31dc2fe07bf05541d-diff_mark_adjust_tp
 * @id cpp/vim/4e677b9c40ccbc5f090971b31dc2fe07bf05541d/diff-mark-adjust-tp
 * @description vim-4e677b9c40ccbc5f090971b31dc2fe07bf05541d-src/diff.c-diff_mark_adjust_tp CVE-2022-2598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdp_299, Variable vi_302, Variable voff_304, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_1, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="df_lnum"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_299
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_302
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voff_304
		and target_0.getThen() instanceof ExprStmt
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="df_lnum"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_299
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_302
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignSubExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignSubExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdp_299, Variable vi_302, Variable voff_304, LogicalAndExpr target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignSubExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="df_lnum"
		and target_1.getExpr().(AssignSubExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_299
		and target_1.getExpr().(AssignSubExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_302
		and target_1.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voff_304
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vi_302, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tp_diffbuf"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_302
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_302
}

predicate func_3(Variable vdp_299, ExprStmt target_3) {
		target_3.getExpr().(AssignSubExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="df_count"
		and target_3.getExpr().(AssignSubExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_299
}

predicate func_4(Variable voff_304, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voff_304
}

from Function func, Variable vdp_299, Variable vi_302, Variable voff_304, ExprStmt target_1, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vdp_299, vi_302, voff_304, target_2, target_3, target_1, target_4)
and func_1(vdp_299, vi_302, voff_304, target_2, target_1)
and func_2(vi_302, target_2)
and func_3(vdp_299, target_3)
and func_4(voff_304, target_4)
and vdp_299.getType().hasName("diff_T *")
and vi_302.getType().hasName("int")
and voff_304.getType().hasName("int")
and vdp_299.getParentScope+() = func
and vi_302.getParentScope+() = func
and voff_304.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
