/**
 * @name linux-21998a351512eba4ed5969006f0c55882d995ada-arch_seccomp_spec_mitigate
 * @id cpp/linux/21998a351512eba4ed5969006f0c55882d995ada/arch_seccomp_spec_mitigate
 * @description linux-21998a351512eba4ed5969006f0c55882d995ada-arch_seccomp_spec_mitigate 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vtask_1215, Variable vspectre_v2_user) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vspectre_v2_user
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ib_prctl_set")
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtask_1215
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3")
}

predicate func_1(Parameter vtask_1215) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ib_prctl_set")
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtask_1215
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3")
}

from Function func, Parameter vtask_1215, Variable vspectre_v2_user
where
func_0(vtask_1215, vspectre_v2_user)
and not func_1(vtask_1215)
and vtask_1215.getType().hasName("task_struct *")
and vtask_1215.getParentScope+() = func
and not vspectre_v2_user.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
