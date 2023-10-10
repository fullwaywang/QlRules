/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-del_match_busid
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/del_match_busid
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-del_match_busid 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vidx_100, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_100
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Variable vidx_100, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_100
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

predicate func_2(Variable vidx_100) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vidx_100
		and target_2.getGreaterOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_3(Variable vidx_100, Variable vbusid_table) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(VariableAccess).getTarget()=vbusid_table
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vidx_100)
}

from Function func, Variable vidx_100, Variable vbusid_table
where
not func_0(vidx_100, func)
and not func_1(vidx_100, func)
and vidx_100.getType().hasName("int")
and func_2(vidx_100)
and func_3(vidx_100, vbusid_table)
and vbusid_table.getType().hasName("bus_id_priv[16]")
and vidx_100.getParentScope+() = func
and not vbusid_table.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
