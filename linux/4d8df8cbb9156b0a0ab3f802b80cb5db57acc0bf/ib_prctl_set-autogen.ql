/**
 * @name linux-4d8df8cbb9156b0a0ab3f802b80cb5db57acc0bf-ib_prctl_set
 * @id cpp/linux/4d8df8cbb9156b0a0ab3f802b80cb5db57acc0bf/ib_prctl_set
 * @description linux-4d8df8cbb9156b0a0ab3f802b80cb5db57acc0bf-ib_prctl_set 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vtask_1169) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("task_spec_ib_force_disable")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtask_1169
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_1(Variable vspectre_v2_user_ibpb, Variable vspectre_v2_user_stibp) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vspectre_v2_user_ibpb
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vspectre_v2_user_stibp
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vspectre_v2_user_stibp
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

from Function func, Parameter vtask_1169, Variable vspectre_v2_user_ibpb, Variable vspectre_v2_user_stibp
where
not func_0(vtask_1169)
and func_1(vspectre_v2_user_ibpb, vspectre_v2_user_stibp)
and vtask_1169.getType().hasName("task_struct *")
and vspectre_v2_user_ibpb.getType().hasName("spectre_v2_user_mitigation")
and vspectre_v2_user_stibp.getType().hasName("spectre_v2_user_mitigation")
and vtask_1169.getParentScope+() = func
and not vspectre_v2_user_ibpb.getParentScope+() = func
and not vspectre_v2_user_stibp.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
