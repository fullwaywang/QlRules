/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-get_busid_priv
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/get_busid_priv
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-get_busid_priv 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vidx_58, Variable vbid_59) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="busid_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbid_59
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vidx_58
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

predicate func_1(Variable vidx_58, Variable vbid_59, Variable vbusid_table) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbid_59
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbusid_table
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_58
		and target_1.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vidx_58
		and target_1.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

from Function func, Variable vidx_58, Variable vbid_59, Variable vbusid_table
where
not func_0(vidx_58, vbid_59)
and func_1(vidx_58, vbid_59, vbusid_table)
and vidx_58.getType().hasName("int")
and vbid_59.getType().hasName("bus_id_priv *")
and vbusid_table.getType().hasName("bus_id_priv[16]")
and vidx_58.getParentScope+() = func
and vbid_59.getParentScope+() = func
and not vbusid_table.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
