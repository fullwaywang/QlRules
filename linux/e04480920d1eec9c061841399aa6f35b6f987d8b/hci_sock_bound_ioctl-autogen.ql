/**
 * @name linux-e04480920d1eec9c061841399aa6f35b6f987d8b-hci_sock_bound_ioctl
 * @id cpp/linux/e04480920d1eec9c061841399aa6f35b6f987d8b/hci_sock_bound_ioctl
 * @description linux-e04480920d1eec9c061841399aa6f35b6f987d8b-hci_sock_bound_ioctl CVE-2021-3573
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsk_930) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("hci_hdev_from_sock")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vsk_930)
}

predicate func_1(Variable vhdev_933) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("IS_ERR")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vhdev_933)
}

predicate func_2(Variable vhdev_933) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("PTR_ERR")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vhdev_933)
}

predicate func_5(Parameter vsk_930) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="hdev"
		and target_5.getQualifier().(VariableAccess).getTarget()=vsk_930)
}

predicate func_6(Variable vhdev_933) {
	exists(NotExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vhdev_933
		and target_6.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-77"
		and target_6.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="77")
}

from Function func, Parameter vsk_930, Variable vhdev_933
where
not func_0(vsk_930)
and not func_1(vhdev_933)
and not func_2(vhdev_933)
and func_5(vsk_930)
and func_6(vhdev_933)
and vsk_930.getType().hasName("sock *")
and vhdev_933.getType().hasName("hci_dev *")
and vsk_930.getParentScope+() = func
and vhdev_933.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
