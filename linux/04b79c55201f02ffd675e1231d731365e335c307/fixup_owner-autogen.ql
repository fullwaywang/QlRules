/**
 * @name linux-04b79c55201f02ffd675e1231d731365e335c307-fixup_owner
 * @id cpp/linux/04b79c55201f02ffd675e1231d731365e335c307/fixup-owner
 * @description linux-04b79c55201f02ffd675e1231d731365e335c307-fixup_owner 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("printk")
		and not target_0.getTarget().hasName("fixup_pi_state_owner")
		and target_0.getArgument(0).(StringLiteral).getValue()="3fixup_owner: ret = %d pi-mutex: %p pi-state %p\n"
		and target_0.getArgument(1).(ErrorExpr).getType() instanceof ErroneousType
		and target_0.getArgument(2).(ValueFieldAccess).getTarget().getName()="owner"
		and target_0.getArgument(2).(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_0.getArgument(3).(PointerFieldAccess).getTarget().getName()="owner"
		and target_0.getArgument(3).(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_16(Parameter vq_2524) {
	exists(EqualityOperation target_16 |
		target_16.getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_16.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_16.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_16.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_16.getAnOperand().(FunctionCall).getTarget().hasName("get_current")
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_18(Parameter vq_2524) {
	exists(PointerFieldAccess target_18 |
		target_18.getTarget().getName()="pi_mutex"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524)
}

predicate func_19(Parameter vq_2524) {
	exists(PointerFieldAccess target_19 |
		target_19.getTarget().getName()="pi_state"
		and target_19.getQualifier().(VariableAccess).getTarget()=vq_2524)
}

predicate func_20(Parameter vuaddr_2524, Parameter vq_2524) {
	exists(FunctionCall target_20 |
		target_20.getTarget().hasName("fixup_pi_state_owner")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vuaddr_2524
		and target_20.getArgument(1).(VariableAccess).getTarget()=vq_2524
		and target_20.getArgument(2).(Literal).getValue()="0")
}

from Function func, Parameter vuaddr_2524, Parameter vq_2524
where
func_0(func)
and func_16(vq_2524)
and func_18(vq_2524)
and func_19(vq_2524)
and vuaddr_2524.getType().hasName("u32 *")
and func_20(vuaddr_2524, vq_2524)
and vq_2524.getType().hasName("futex_q *")
and vuaddr_2524.getParentScope+() = func
and vq_2524.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
