/**
 * @name linux-34b1a1ce1458f50ef27c54e28eb9b1947012907a-futex_wait_requeue_pi
 * @id cpp/linux/34b1a1ce1458f50ef27c54e28eb9b1947012907a/futex_wait_requeue_pi
 * @description linux-34b1a1ce1458f50ef27c54e28eb9b1947012907a-futex_wait_requeue_pi 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vret_3176) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vret_3176
		and target_0.getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen() instanceof BlockStmt)
}

predicate func_1(Variable vq_3175) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3175
		and target_1.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand() instanceof FunctionCall)
}

predicate func_2(Variable vq_3175) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="pi_state"
		and target_2.getQualifier().(VariableAccess).getTarget()=vq_3175)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vpi_state_3171, Variable vq_3175) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpi_state_3171
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof ValueFieldAccess
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_pi_state")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_3171
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3175
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="owner"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3175
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current"))
}

predicate func_7(Variable vpi_state_3171, Variable vq_3175, Variable vret_3176) {
	exists(IfStmt target_7 |
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vret_3176
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3175
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpi_state_3171
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="pi_state"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3175
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("get_pi_state")
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_3171
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="rt_waiter"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_3175)
}

predicate func_10(Variable vpi_state_3171, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(VariableAccess).getTarget()=vpi_state_3171
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rt_mutex_futex_unlock")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_3171
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("put_pi_state")
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpi_state_3171
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

from Function func, Variable vpi_state_3171, Variable vq_3175, Variable vret_3176
where
func_0(vret_3176)
and func_1(vq_3175)
and func_2(vq_3175)
and func_3(func)
and func_4(vpi_state_3171, vq_3175)
and func_7(vpi_state_3171, vq_3175, vret_3176)
and func_10(vpi_state_3171, func)
and vpi_state_3171.getType().hasName("futex_pi_state *")
and vq_3175.getType().hasName("futex_q")
and vret_3176.getType().hasName("int")
and vpi_state_3171.getParentScope+() = func
and vq_3175.getParentScope+() = func
and vret_3176.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
