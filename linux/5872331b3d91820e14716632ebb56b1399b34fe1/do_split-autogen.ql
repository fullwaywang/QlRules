/**
 * @name linux-5872331b3d91820e14716632ebb56b1399b34fe1-do_split
 * @id cpp/linux/5872331b3d91820e14716632ebb56b1399b34fe1/do_split
 * @description linux-5872331b3d91820e14716632ebb56b1399b34fe1-do_split 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_1822, Variable vsplit_1828, Variable vi_1831, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_1831
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsplit_1828
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_1822
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_0))
}

predicate func_1(Variable vcount_1822, Variable vsplit_1828, Variable vmove_1828, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsplit_1828
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_1822
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmove_1828
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vcount_1822, Variable vi_1831) {
	exists(SubExpr target_2 |
		target_2.getLeftOperand().(VariableAccess).getTarget()=vcount_1822
		and target_2.getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_1831)
}

predicate func_3(Variable vmap_1826, Variable vi_1831) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(VariableAccess).getTarget()=vmap_1826
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vi_1831)
}

from Function func, Variable vcount_1822, Variable vmap_1826, Variable vsplit_1828, Variable vmove_1828, Variable vi_1831
where
not func_0(vcount_1822, vsplit_1828, vi_1831, func)
and func_1(vcount_1822, vsplit_1828, vmove_1828, func)
and vcount_1822.getType().hasName("unsigned int")
and func_2(vcount_1822, vi_1831)
and vsplit_1828.getType().hasName("unsigned int")
and vmove_1828.getType().hasName("unsigned int")
and vi_1831.getType().hasName("int")
and func_3(vmap_1826, vi_1831)
and vcount_1822.getParentScope+() = func
and vmap_1826.getParentScope+() = func
and vsplit_1828.getParentScope+() = func
and vmove_1828.getParentScope+() = func
and vi_1831.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
