/**
 * @name vim-156d3911952d73b03d7420dc3540215247db0fe8-suggest_trie_walk
 * @id cpp/vim/156d3911952d73b03d7420dc3540215247db0fe8/suggest-trie-walk
 * @description vim-156d3911952d73b03d7420dc3540215247db0fe8-src/spellsuggest.c-suggest_trie_walk CVE-2022-2126
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_1274, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ts_fidx"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1274
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsp_1274, ExprStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="ts_isdiff"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1274
		and target_1.getAnOperand().(Literal).getValue()="2"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vsp_1274, ExprStmt target_2) {
		target_2.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ts_fidx"
		and target_2.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1274
}

predicate func_3(Variable vsp_1274, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ts_isdiff"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1274
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

from Function func, Variable vsp_1274, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vsp_1274, target_2, target_3, target_1)
and func_1(vsp_1274, target_2, target_1)
and func_2(vsp_1274, target_2)
and func_3(vsp_1274, target_3)
and vsp_1274.getType().hasName("trystate_T *")
and vsp_1274.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
