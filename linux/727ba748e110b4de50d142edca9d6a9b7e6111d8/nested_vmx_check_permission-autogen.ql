/**
 * @name linux-727ba748e110b4de50d142edca9d6a9b7e6111d8-nested_vmx_check_permission
 * @id cpp/linux/727ba748e110b4de50d142edca9d6a9b7e6111d8/nested_vmx_check_permission
 * @description linux-727ba748e110b4de50d142edca9d6a9b7e6111d8-nested_vmx_check_permission 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vvcpu_7965, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("vmx_get_cpl")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_7965
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kvm_queue_exception")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_7965
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="6"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0))
}

from Function func, Parameter vvcpu_7965
where
not func_0(vvcpu_7965, func)
and vvcpu_7965.getType().hasName("kvm_vcpu *")
and vvcpu_7965.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
