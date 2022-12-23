/**
 * @name linux-3b0541791453fbe7f42867e310e0c9eb6295364d-sas_ex_discover_expander
 * @id cpp/linux/3b0541791453fbe7f42867e310e0c9eb6295364d/sas_ex_discover_expander
 * @description linux-3b0541791453fbe7f42867e310e0c9eb6295364d-sas_ex_discover_expander 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vphy_955, Variable vres_960) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sas_port_delete")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="port"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_955
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vres_960)
}

predicate func_1(Variable vphy_955, Variable vres_960) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="port"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_955
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vres_960)
}

predicate func_2(Variable vphy_955, Variable vchild_956, Parameter vparent_952) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sas_ex_get_linkrate")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vparent_952
		and target_2.getArgument(1).(VariableAccess).getTarget()=vchild_956
		and target_2.getArgument(2).(VariableAccess).getTarget()=vphy_955)
}

from Function func, Variable vphy_955, Variable vchild_956, Variable vres_960, Parameter vparent_952
where
not func_0(vphy_955, vres_960)
and not func_1(vphy_955, vres_960)
and vphy_955.getType().hasName("ex_phy *")
and func_2(vphy_955, vchild_956, vparent_952)
and vchild_956.getType().hasName("domain_device *")
and vres_960.getType().hasName("int")
and vparent_952.getType().hasName("domain_device *")
and vphy_955.getParentScope+() = func
and vchild_956.getParentScope+() = func
and vres_960.getParentScope+() = func
and vparent_952.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
