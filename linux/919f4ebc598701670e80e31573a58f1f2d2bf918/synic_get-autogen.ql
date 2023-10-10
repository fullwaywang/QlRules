/**
 * @name linux-919f4ebc598701670e80e31573a58f1f2d2bf918-synic_get
 * @id cpp/linux/919f4ebc598701670e80e31573a58f1f2d2bf918/synic-get
 * @description linux-919f4ebc598701670e80e31573a58f1f2d2bf918-synic_get 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvcpu_158) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("to_hv_vcpu")
		and target_0.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_158
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Variable vvcpu_158) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vvcpu_158
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Parameter vkvm_156, Parameter vvpidx_156, Variable vvcpu_158) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vvcpu_158
		and target_2.getRValue().(FunctionCall).getTarget().hasName("get_vcpu_by_vpidx")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkvm_156
		and target_2.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvpidx_156)
}

from Function func, Parameter vkvm_156, Parameter vvpidx_156, Variable vvcpu_158
where
not func_0(vvcpu_158)
and func_1(vvcpu_158)
and vvcpu_158.getType().hasName("kvm_vcpu *")
and func_2(vkvm_156, vvpidx_156, vvcpu_158)
and vkvm_156.getParentScope+() = func
and vvpidx_156.getParentScope+() = func
and vvcpu_158.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
