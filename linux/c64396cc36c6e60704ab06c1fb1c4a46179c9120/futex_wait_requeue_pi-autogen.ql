/**
 * @name linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-futex_wait_requeue_pi
 * @id cpp/linux/c64396cc36c6e60704ab06c1fb1c4a46179c9120/futex-wait-requeue-pi
 * @description linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-futex_wait_requeue_pi 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_3191) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vret_3191
		and target_0.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_3191
		and target_0.getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_0.getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vret_3191
		and target_0.getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0")
}

predicate func_1(Variable vq_3190) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3190
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand() instanceof FunctionCall)
}

predicate func_2(Variable vq_3190) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="pi_state"
		and target_2.getQualifier().(VariableAccess).getTarget()=vq_3190)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Variable vpi_state_3186, Variable vq_3190, Variable vret_3191) {
	exists(IfStmt target_7 |
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vret_3191
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpi_state_3186
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof ValueFieldAccess
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_pi_state")
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_3186
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3190
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="owner"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3190
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current"))
}

predicate func_10(Variable vpi_state_3186, Variable vq_3190, Variable vret_3191) {
	exists(IfStmt target_10 |
		target_10.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vret_3191
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3190
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpi_state_3186
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3190
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_pi_state")
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_3186
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="rt_waiter"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3190)
}

predicate func_13(Variable vpi_state_3186, Function func) {
	exists(IfStmt target_13 |
		target_13.getCondition().(VariableAccess).getTarget()=vpi_state_3186
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rt_mutex_futex_unlock")
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_3186
		and target_13.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("put_pi_state")
		and target_13.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_3186
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

from Function func, Variable vpi_state_3186, Variable vq_3190, Variable vret_3191
where
not func_0(vret_3191)
and func_1(vq_3190)
and func_2(vq_3190)
and func_3(func)
and func_6(func)
and func_7(vpi_state_3186, vq_3190, vret_3191)
and func_10(vpi_state_3186, vq_3190, vret_3191)
and func_13(vpi_state_3186, func)
and vpi_state_3186.getType().hasName("futex_pi_state *")
and vq_3190.getType().hasName("futex_q")
and vret_3191.getType().hasName("int")
and vpi_state_3186.getParentScope+() = func
and vq_3190.getParentScope+() = func
and vret_3191.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
