/**
 * @name vim-2de9b7c7c8791da8853a9a7ca9c467867465b655-find_start_brace
 * @id cpp/vim/2de9b7c7c8791da8853a9a7ca9c467867465b655/find-start-brace
 * @description vim-2de9b7c7c8791da8853a9a7ca9c467867465b655-src/cindent.c-find_start_brace CVE-2021-3984
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpos_1642, Variable vcurwin, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_0.getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpos_1642
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcurwin, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="w_cursor"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_2(Variable vpos_1642, VariableAccess target_2) {
		target_2.getTarget()=vpos_1642
}

predicate func_3(Variable vpos_1642, Variable vcurwin, AssignExpr target_3) {
		target_3.getLValue().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="lnum"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpos_1642
}

predicate func_4(Variable vpos_1642, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vpos_1642
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vcurwin, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_6(Variable vcurwin, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

from Function func, Variable vpos_1642, Variable vcurwin, PointerFieldAccess target_1, VariableAccess target_2, AssignExpr target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vpos_1642, vcurwin, target_4, target_5, target_6)
and func_1(vcurwin, target_1)
and func_2(vpos_1642, target_2)
and func_3(vpos_1642, vcurwin, target_3)
and func_4(vpos_1642, target_4)
and func_5(vcurwin, target_5)
and func_6(vcurwin, target_6)
and vpos_1642.getType().hasName("pos_T *")
and vcurwin.getType().hasName("win_T *")
and vpos_1642.getParentScope+() = func
and not vcurwin.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
