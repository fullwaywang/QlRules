/**
 * @name vim-e0f869196930ef5f25a0ac41c9215b09c9ce2d3c-scrolldown
 * @id cpp/vim/e0f869196930ef5f25a0ac41c9215b09c9ce2d3c/scrolldown
 * @description vim-e0f869196930ef5f25a0ac41c9215b09c9ce2d3c-src/move.c-scrolldown CVE-2023-1127
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwidth2_1590, BlockStmt target_2, ConditionalExpr target_3, RelationalOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth2_1590
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vwidth2_1590, Variable vcol_1730, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vcol_1730
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vwidth2_1590
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vwidth2_1590, Variable vcol_1730, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vcol_1730
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vwidth2_1590
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcol_1730
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(RemExpr).getLeftOperand().(VariableAccess).getTarget()=vcol_1730
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vwidth2_1590
}

predicate func_3(Variable vwidth2_1590, ConditionalExpr target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(Literal).getValue()="0"
		and target_3.getElse().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getElse().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vwidth2_1590
}

from Function func, Variable vwidth2_1590, Variable vcol_1730, RelationalOperation target_1, BlockStmt target_2, ConditionalExpr target_3
where
not func_0(vwidth2_1590, target_2, target_3, target_1)
and func_1(vwidth2_1590, vcol_1730, target_2, target_1)
and func_2(vwidth2_1590, vcol_1730, target_2)
and func_3(vwidth2_1590, target_3)
and vwidth2_1590.getType().hasName("int")
and vcol_1730.getType().hasName("int")
and vwidth2_1590.getParentScope+() = func
and vcol_1730.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
