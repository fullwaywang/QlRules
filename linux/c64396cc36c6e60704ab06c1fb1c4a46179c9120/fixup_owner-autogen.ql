/**
 * @name linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-fixup_owner
 * @id cpp/linux/c64396cc36c6e60704ab06c1fb1c4a46179c9120/fixup-owner
 * @description linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-fixup_owner 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(VariableDeclarationEntry target_0 |
		target_0.getVariable().getInitializer().(Initializer).getExpr() instanceof Literal
		and target_0.getDeclaration().getParentScope+() = func)
}

predicate func_2(Variable vret_2526) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vret_2526)
}

predicate func_4(Variable vret_2526) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("printk")
		and not target_4.getTarget().hasName("fixup_pi_state_owner")
		and target_4.getArgument(0).(StringLiteral).getValue()="3fixup_owner: ret = %d pi-mutex: %p pi-state %p\n"
		and target_4.getArgument(1).(VariableAccess).getTarget()=vret_2526
		and target_4.getArgument(2).(ValueFieldAccess).getTarget().getName()="owner"
		and target_4.getArgument(2).(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_4.getArgument(3).(PointerFieldAccess).getTarget().getName()="owner"
		and target_4.getArgument(3).(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vq_2524) {
	exists(ReturnStmt target_6 |
		target_6.getExpr() instanceof FunctionCall
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="owner"
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current"))
}

predicate func_22(Parameter vuaddr_2524, Parameter vq_2524) {
	exists(FunctionCall target_22 |
		target_22.getTarget().hasName("fixup_pi_state_owner")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vuaddr_2524
		and target_22.getArgument(1).(VariableAccess).getTarget()=vq_2524
		and target_22.getArgument(2).(FunctionCall).getTarget().hasName("get_current"))
}

predicate func_23(Parameter vuaddr_2524, Parameter vq_2524) {
	exists(FunctionCall target_23 |
		target_23.getTarget().hasName("fixup_pi_state_owner")
		and target_23.getArgument(0).(VariableAccess).getTarget()=vuaddr_2524
		and target_23.getArgument(1).(VariableAccess).getTarget()=vq_2524
		and target_23.getArgument(2).(Literal).getValue()="0")
}

predicate func_24(Parameter vq_2524) {
	exists(EqualityOperation target_24 |
		target_24.getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_24.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_24.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_24.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_24.getAnOperand().(FunctionCall).getTarget().hasName("get_current")
		and target_24.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_25(Function func) {
	exists(Literal target_25 |
		target_25.getValue()="0"
		and target_25.getEnclosingFunction() = func)
}

predicate func_27(Variable vret_2526) {
	exists(AssignExpr target_27 |
		target_27.getLValue().(VariableAccess).getTarget()=vret_2526
		and target_27.getRValue() instanceof FunctionCall)
}

predicate func_28(Parameter vlocked_2524, Variable vret_2526) {
	exists(ConditionalExpr target_28 |
		target_28.getCondition().(VariableAccess).getTarget()=vret_2526
		and target_28.getThen().(VariableAccess).getTarget()=vret_2526
		and target_28.getElse().(VariableAccess).getTarget()=vlocked_2524)
}

predicate func_29(Variable vret_2526) {
	exists(AssignExpr target_29 |
		target_29.getLValue().(VariableAccess).getTarget()=vret_2526
		and target_29.getRValue() instanceof FunctionCall)
}

predicate func_31(Parameter vq_2524) {
	exists(PointerFieldAccess target_31 |
		target_31.getTarget().getName()="pi_mutex"
		and target_31.getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_31.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524)
}

predicate func_32(Parameter vq_2524) {
	exists(PointerFieldAccess target_32 |
		target_32.getTarget().getName()="pi_state"
		and target_32.getQualifier().(VariableAccess).getTarget()=vq_2524)
}

from Function func, Parameter vuaddr_2524, Parameter vq_2524, Parameter vlocked_2524, Variable vret_2526
where
func_0(func)
and func_2(vret_2526)
and func_4(vret_2526)
and not func_5(func)
and not func_6(vq_2524)
and func_22(vuaddr_2524, vq_2524)
and func_23(vuaddr_2524, vq_2524)
and func_24(vq_2524)
and func_25(func)
and func_27(vret_2526)
and func_28(vlocked_2524, vret_2526)
and func_29(vret_2526)
and func_31(vq_2524)
and func_32(vq_2524)
and vuaddr_2524.getType().hasName("u32 *")
and vq_2524.getType().hasName("futex_q *")
and vlocked_2524.getType().hasName("int")
and vuaddr_2524.getParentScope+() = func
and vq_2524.getParentScope+() = func
and vlocked_2524.getParentScope+() = func
and vret_2526.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
