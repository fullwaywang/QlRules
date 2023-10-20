/**
 * @name vim-232bdaaca98c34a99ffadf27bf6ee08be6cc8f6a-nv_scroll
 * @id cpp/vim/232bdaaca98c34a99ffadf27bf6ee08be6cc8f6a/nv-scroll
 * @description vim-232bdaaca98c34a99ffadf27bf6ee08be6cc8f6a-src/normal.c-nv_scroll CVE-2023-0288
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcurwin, AddressOfExpr target_2, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="w_topline"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_0.getThen() instanceof ExprStmt
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PrefixDecrExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcurwin, ExprStmt target_1) {
		target_1.getExpr().(PrefixDecrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_1.getExpr().(PrefixDecrExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_1.getExpr().(PrefixDecrExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_2(Variable vcurwin, AddressOfExpr target_2) {
		target_2.getOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

from Function func, Variable vcurwin, ExprStmt target_1, AddressOfExpr target_2
where
not func_0(vcurwin, target_2, target_1)
and func_1(vcurwin, target_1)
and func_2(vcurwin, target_2)
and vcurwin.getType().hasName("win_T *")
and not vcurwin.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
