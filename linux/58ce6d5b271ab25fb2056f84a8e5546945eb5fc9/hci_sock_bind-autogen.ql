/**
 * @name linux-58ce6d5b271ab25fb2056f84a8e5546945eb5fc9-hci_sock_bind
 * @id cpp/linux/58ce6d5b271ab25fb2056f84a8e5546945eb5fc9/hci_sock_bind
 * @description linux-58ce6d5b271ab25fb2056f84a8e5546945eb5fc9-hci_sock_bind CVE-2021-3573
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsk_1087, Variable vhdev_1088, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhdev_1088
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hdev"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_1087
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0))
}

predicate func_1(Variable vsk_1087, Variable vhdev_1088, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vhdev_1088
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("test_bit")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dev_flags"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_1088
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hdev"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_1087
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="skc_state"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_1087
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hci_dev_put")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_1088
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1))
}

predicate func_5(Variable vhdev_1088, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhdev_1088
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_5))
}

predicate func_6(Variable vsk_1087) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("lock_sock")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vsk_1087)
}

from Function func, Variable vsk_1087, Variable vhdev_1088
where
not func_0(vsk_1087, vhdev_1088, func)
and not func_1(vsk_1087, vhdev_1088, func)
and not func_5(vhdev_1088, func)
and vsk_1087.getType().hasName("sock *")
and func_6(vsk_1087)
and vhdev_1088.getType().hasName("hci_dev *")
and vsk_1087.getParentScope+() = func
and vhdev_1088.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
