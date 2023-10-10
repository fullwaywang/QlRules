/**
 * @name linux-cfa39381173d5f969daf43582c95ad679189cbc9-kvm_ioctl_create_device
 * @id cpp/linux/cfa39381173d5f969daf43582c95ad679189cbc9/kvm-ioctl-create-device
 * @description linux-cfa39381173d5f969daf43582c95ad679189cbc9-kvm_ioctl_create_device CVE-2019-6974
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_2971, Parameter vkvm_2965) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kvm_put_kvm")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkvm_2965
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_2971
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vkvm_2965) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="lock"
		and target_1.getQualifier().(VariableAccess).getTarget()=vkvm_2965)
}

from Function func, Variable vret_2971, Parameter vkvm_2965
where
not func_0(vret_2971, vkvm_2965)
and vret_2971.getType().hasName("int")
and vkvm_2965.getType().hasName("kvm *")
and func_1(vkvm_2965)
and vret_2971.getParentScope+() = func
and vkvm_2965.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
