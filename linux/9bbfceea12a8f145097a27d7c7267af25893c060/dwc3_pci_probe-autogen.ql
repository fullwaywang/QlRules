/**
 * @name linux-9bbfceea12a8f145097a27d7c7267af25893c060-dwc3_pci_probe
 * @id cpp/linux/9bbfceea12a8f145097a27d7c7267af25893c060/dwc3_pci_probe
 * @description linux-9bbfceea12a8f145097a27d7c7267af25893c060-dwc3_pci_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vret_219) {
	exists(GotoStmt target_0 |
		target_0.toString() = "goto ..."
		and target_0.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_219
		and target_0.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_1(Variable vret_219) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=vret_219
		and target_1.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_219
		and target_1.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Variable vret_219
where
not func_0(vret_219)
and func_1(vret_219)
and vret_219.getType().hasName("int")
and vret_219.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
