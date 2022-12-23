/**
 * @name linux-a0ecd6fdbf5d648123a7315c695fb6850d702835-komeda_wb_connector_add
 * @id cpp/linux/a0ecd6fdbf5d648123a7315c695fb6850d702835/komeda-wb-connector-add
 * @description linux-a0ecd6fdbf5d648123a7315c695fb6850d702835-komeda_wb_connector_add 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verr_145, Variable vkwb_conn_142) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkwb_conn_142
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_145)
}

predicate func_1(Variable verr_145) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=verr_145
		and target_1.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_145)
}

predicate func_2(Variable vkwb_conn_142) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="wb_layer"
		and target_2.getQualifier().(VariableAccess).getTarget()=vkwb_conn_142)
}

from Function func, Variable verr_145, Variable vkwb_conn_142
where
not func_0(verr_145, vkwb_conn_142)
and func_1(verr_145)
and verr_145.getType().hasName("int")
and vkwb_conn_142.getType().hasName("komeda_wb_connector *")
and func_2(vkwb_conn_142)
and verr_145.getParentScope+() = func
and vkwb_conn_142.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
