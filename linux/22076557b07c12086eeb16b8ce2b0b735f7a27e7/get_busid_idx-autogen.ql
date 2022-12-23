/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-get_busid_idx
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/get_busid_idx
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-get_busid_idx 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vi_44) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_44)
}

predicate func_1(Variable vi_44, Parameter vbusid_42) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_44
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_44
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbusid_42
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="32")
}

predicate func_3(Variable vi_44) {
	exists(PostfixIncrExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vi_44)
}

predicate func_4(Variable vi_44, Variable vidx_45) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vidx_45
		and target_4.getRValue().(VariableAccess).getTarget()=vi_44)
}

from Function func, Variable vi_44, Variable vidx_45, Parameter vbusid_42
where
not func_0(vi_44)
and not func_1(vi_44, vbusid_42)
and vi_44.getType().hasName("int")
and func_3(vi_44)
and func_4(vi_44, vidx_45)
and vidx_45.getType().hasName("int")
and vbusid_42.getType().hasName("const char *")
and vi_44.getParentScope+() = func
and vidx_45.getParentScope+() = func
and vbusid_42.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
