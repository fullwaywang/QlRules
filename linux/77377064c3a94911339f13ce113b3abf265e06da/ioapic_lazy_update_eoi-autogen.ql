/**
 * @name linux-77377064c3a94911339f13ce113b3abf265e06da-ioapic_lazy_update_eoi
 * @id cpp/linux/77377064c3a94911339f13ce113b3abf265e06da/ioapic_lazy_update_eoi
 * @description linux-77377064c3a94911339f13ce113b3abf265e06da-ioapic_lazy_update_eoi CVE-2020-27152
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter virq_185, Variable vvcpu_188, Variable ventry_189, Parameter vioapic_185) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kvm_ioapic_update_eoi_one")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_188
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vioapic_185
		and target_0.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="trig_mode"
		and target_0.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fields"
		and target_0.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_189
		and target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=virq_185)
}

from Function func, Parameter virq_185, Variable vvcpu_188, Variable ventry_189, Parameter vioapic_185
where
func_0(virq_185, vvcpu_188, ventry_189, vioapic_185)
and virq_185.getType().hasName("int")
and vvcpu_188.getType().hasName("kvm_vcpu *")
and ventry_189.getType().hasName("kvm_ioapic_redirect_entry *")
and vioapic_185.getType().hasName("kvm_ioapic *")
and virq_185.getParentScope+() = func
and vvcpu_188.getParentScope+() = func
and ventry_189.getParentScope+() = func
and vioapic_185.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
