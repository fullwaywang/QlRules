/**
 * @name linux-e04480920d1eec9c061841399aa6f35b6f987d8b-hci_sock_getname
 * @id cpp/linux/e04480920d1eec9c061841399aa6f35b6f987d8b/hci_sock_getname
 * @description linux-e04480920d1eec9c061841399aa6f35b6f987d8b-hci_sock_getname CVE-2021-3573
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsk_1371) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("hci_hdev_from_sock")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vsk_1371)
}

predicate func_1(Variable vhdev_1372) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("IS_ERR")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vhdev_1372)
}

predicate func_2(Variable vhdev_1372) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("PTR_ERR")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vhdev_1372)
}

predicate func_5(Variable vsk_1371) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="hdev"
		and target_5.getQualifier().(VariableAccess).getTarget()=vsk_1371)
}

predicate func_6(Variable vhdev_1372, Variable verr_1373) {
	exists(NotExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vhdev_1372
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_1373
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="77"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ...")
}

from Function func, Variable vsk_1371, Variable vhdev_1372, Variable verr_1373
where
not func_0(vsk_1371)
and not func_1(vhdev_1372)
and not func_2(vhdev_1372)
and func_5(vsk_1371)
and func_6(vhdev_1372, verr_1373)
and vsk_1371.getType().hasName("sock *")
and vhdev_1372.getType().hasName("hci_dev *")
and verr_1373.getType().hasName("int")
and vsk_1371.getParentScope+() = func
and vhdev_1372.getParentScope+() = func
and verr_1373.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
