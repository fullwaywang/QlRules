/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-add_match_busid
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/add_match_busid
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-add_match_busid 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vi_72) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_72)
}

predicate func_1(Variable vi_72) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_72
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_72
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_3(Variable vi_72) {
	exists(PostfixIncrExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vi_72)
}

predicate func_4(Variable vi_72, Variable vbusid_table) {
	exists(ArrayExpr target_4 |
		target_4.getArrayBase().(VariableAccess).getTarget()=vbusid_table
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vi_72)
}

from Function func, Variable vi_72, Variable vbusid_table
where
not func_0(vi_72)
and not func_1(vi_72)
and vi_72.getType().hasName("int")
and func_3(vi_72)
and func_4(vi_72, vbusid_table)
and vbusid_table.getType().hasName("bus_id_priv[16]")
and vi_72.getParentScope+() = func
and not vbusid_table.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
