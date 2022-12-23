/**
 * @name linux-34b1a1ce1458f50ef27c54e28eb9b1947012907a-futex_lock_pi
 * @id cpp/linux/34b1a1ce1458f50ef27c54e28eb9b1947012907a/futex_lock_pi
 * @description linux-34b1a1ce1458f50ef27c54e28eb9b1947012907a-futex_lock_pi 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Variable vpi_state_2759, Variable vq_2763, Variable vret_2764, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vret_2764
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2763
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpi_state_2759
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2763
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_pi_state")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_2759
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_4(Variable vpi_state_2759, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(VariableAccess).getTarget()=vpi_state_2759
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rt_mutex_futex_unlock")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_2759
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("put_pi_state")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_2759
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Variable vpi_state_2759, Variable vq_2763, Variable vret_2764
where
func_0(func)
and func_1(vpi_state_2759, vq_2763, vret_2764, func)
and func_4(vpi_state_2759, func)
and vpi_state_2759.getType().hasName("futex_pi_state *")
and vq_2763.getType().hasName("futex_q")
and vret_2764.getType().hasName("int")
and vpi_state_2759.getParentScope+() = func
and vq_2763.getParentScope+() = func
and vret_2764.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
