/**
 * @name linux-727ba748e110b4de50d142edca9d6a9b7e6111d8-handle_vmon
 * @id cpp/linux/727ba748e110b4de50d142edca9d6a9b7e6111d8/handle_vmon
 * @description linux-727ba748e110b4de50d142edca9d6a9b7e6111d8-handle_vmon 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vvcpu_7885, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("vmx_get_cpl")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_7885
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kvm_queue_exception")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_7885
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="6"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vvcpu_7885) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("kvm_queue_exception")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vvcpu_7885
		and target_3.getArgument(1).(Literal).getValue()="6")
}

from Function func, Parameter vvcpu_7885
where
not func_0(vvcpu_7885, func)
and vvcpu_7885.getType().hasName("kvm_vcpu *")
and func_3(vvcpu_7885)
and vvcpu_7885.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
