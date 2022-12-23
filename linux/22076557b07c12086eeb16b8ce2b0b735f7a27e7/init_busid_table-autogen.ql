/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-init_busid_table
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/init_busid_table
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-init_busid_table 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vbusid_table) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="1024"
		and target_0.getExprOperand().(VariableAccess).getTarget()=vbusid_table)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		func.getEntryPoint().(BlockStmt).getStmt(0)=target_1)
}

predicate func_2(Variable vbusid_table, Function func) {
	exists(ForStmt target_2 |
		target_2.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="16"
		and target_2.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_2.getStmt().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spinlock_check")
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbusid_table
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__raw_spin_lock_init")
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="rlock"
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="busid_lock"
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbusid_table
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="&(&busid_table[i].busid_lock)->rlock"
		and target_2.getStmt().(DoStmt).getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("lock_class_key")
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_2))
}

from Function func, Variable vbusid_table
where
func_0(vbusid_table)
and not func_1(func)
and not func_2(vbusid_table, func)
and vbusid_table.getType().hasName("bus_id_priv[16]")
and not vbusid_table.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
