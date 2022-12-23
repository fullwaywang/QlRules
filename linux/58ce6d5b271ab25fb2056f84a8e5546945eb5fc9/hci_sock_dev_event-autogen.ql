/**
 * @name linux-58ce6d5b271ab25fb2056f84a8e5546945eb5fc9-hci_sock_dev_event
 * @id cpp/linux/58ce6d5b271ab25fb2056f84a8e5546945eb5fc9/hci_sock_dev_event
 * @description linux-58ce6d5b271ab25fb2056f84a8e5546945eb5fc9-hci_sock_dev_event CVE-2021-3573
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsk_760) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("lock_sock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_760)
}

predicate func_1(Variable vsk_760, Parameter vhdev_734) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hdev"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_760
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hdev"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_760
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhdev_734)
}

predicate func_2(Variable vsk_760, Parameter vhdev_734) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="skc_state"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_760
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hdev"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_760
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhdev_734)
}

predicate func_3(Variable vsk_760, Parameter vhdev_734) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("hci_dev_put")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_734
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hdev"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_760
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhdev_734)
}

predicate func_4(Variable vsk_760) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("release_sock")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_760)
}

from Function func, Variable vsk_760, Parameter vhdev_734
where
func_0(vsk_760)
and func_1(vsk_760, vhdev_734)
and func_2(vsk_760, vhdev_734)
and func_3(vsk_760, vhdev_734)
and func_4(vsk_760)
and vsk_760.getType().hasName("sock *")
and vhdev_734.getType().hasName("hci_dev *")
and vsk_760.getParentScope+() = func
and vhdev_734.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
