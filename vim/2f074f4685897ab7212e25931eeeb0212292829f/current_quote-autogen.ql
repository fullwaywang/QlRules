/**
 * @name vim-2f074f4685897ab7212e25931eeeb0212292829f-current_quote
 * @id cpp/vim/2f074f4685897ab7212e25931eeeb0212292829f/current-quote
 * @description vim-2f074f4685897ab7212e25931eeeb0212292829f-src/textobject.c-current_quote CVE-2022-2124
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vline_1727, Variable vi_1736, ExprStmt target_2, EqualityOperation target_3, RelationalOperation target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_1727
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1736
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BreakStmt).toString() = "break;"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_4.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vquotechar_1725, Variable vline_1727, Variable vselected_quote_1735, Variable vi_1736, RelationalOperation target_4, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_1727
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_1736
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquotechar_1725
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vselected_quote_1735
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_1.getParent().(WhileStmt).getCondition()=target_4
}

predicate func_2(Parameter vquotechar_1725, Variable vline_1727, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquotechar_1725
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_1727
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="col"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_1727
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquotechar_1725
}

predicate func_3(Parameter vquotechar_1725, Variable vline_1727, Variable vi_1736, EqualityOperation target_3) {
		target_3.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_1727
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_1736
		and target_3.getAnOperand().(VariableAccess).getTarget()=vquotechar_1725
}

predicate func_4(Variable vi_1736, RelationalOperation target_4) {
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vi_1736
}

from Function func, Parameter vquotechar_1725, Variable vline_1727, Variable vselected_quote_1735, Variable vi_1736, IfStmt target_1, ExprStmt target_2, EqualityOperation target_3, RelationalOperation target_4
where
not func_0(vline_1727, vi_1736, target_2, target_3, target_4)
and func_1(vquotechar_1725, vline_1727, vselected_quote_1735, vi_1736, target_4, target_1)
and func_2(vquotechar_1725, vline_1727, target_2)
and func_3(vquotechar_1725, vline_1727, vi_1736, target_3)
and func_4(vi_1736, target_4)
and vquotechar_1725.getType().hasName("int")
and vline_1727.getType().hasName("char_u *")
and vselected_quote_1735.getType().hasName("int")
and vi_1736.getType().hasName("int")
and vquotechar_1725.getParentScope+() = func
and vline_1727.getParentScope+() = func
and vselected_quote_1735.getParentScope+() = func
and vi_1736.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
