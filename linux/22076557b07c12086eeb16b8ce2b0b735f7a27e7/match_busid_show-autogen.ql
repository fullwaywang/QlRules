/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-match_busid_show
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/match_busid_show
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-match_busid_show 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vi_126) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_126)
}

predicate func_1(Variable vi_126) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("bus_id_priv[16]")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_126)
}

predicate func_2(Variable vi_126, Variable vout_127, Variable vbusid_table) {
	exists(IfStmt target_2 |
		target_2.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="name"
		and target_2.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbusid_table
		and target_2.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_126
		and target_2.getCondition().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vout_127
		and target_2.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getTarget().hasName("sprintf")
		and target_2.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_127
		and target_2.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s "
		and target_2.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="name"
		and target_2.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbusid_table
		and target_2.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_126)
}

predicate func_3(Variable vi_126) {
	exists(PostfixIncrExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vi_126)
}

from Function func, Variable vi_126, Variable vout_127, Variable vbusid_table
where
not func_0(vi_126)
and not func_1(vi_126)
and func_2(vi_126, vout_127, vbusid_table)
and vi_126.getType().hasName("int")
and func_3(vi_126)
and vout_127.getType().hasName("char *")
and vbusid_table.getType().hasName("bus_id_priv[16]")
and vi_126.getParentScope+() = func
and vout_127.getParentScope+() = func
and not vbusid_table.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
