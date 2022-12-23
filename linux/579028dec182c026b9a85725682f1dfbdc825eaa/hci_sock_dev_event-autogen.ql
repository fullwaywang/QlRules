/**
 * @name linux-579028dec182c026b9a85725682f1dfbdc825eaa-hci_sock_dev_event
 * @id cpp/linux/579028dec182c026b9a85725682f1dfbdc825eaa/hci-sock-dev-event
 * @description linux-579028dec182c026b9a85725682f1dfbdc825eaa-hci_sock_dev_event CVE-2021-3564
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_raw_spin_lock_nested")
		and not target_0.getTarget().hasName("lock_sock")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("spinlock_check")
		and target_0.getArgument(0).(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_0.getArgument(1).(Literal).getValue()="1"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("spin_unlock")
		and not target_1.getTarget().hasName("release_sock")
		and target_1.getArgument(0).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_1.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(DoStmt target_4 |
		target_4.getCondition().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vsk_760) {
	exists(AddressOfExpr target_5 |
		target_5.getOperand().(ValueFieldAccess).getTarget().getName()="slock"
		and target_5.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sk_lock"
		and target_5.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_760
		and target_5.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("spinlock_check"))
}

predicate func_6(Variable vsk_760) {
	exists(ValueFieldAccess target_6 |
		target_6.getTarget().getName()="slock"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="sk_lock"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_760)
}

from Function func, Variable vsk_760
where
func_0(func)
and func_1(func)
and func_4(func)
and func_5(vsk_760)
and func_6(vsk_760)
and vsk_760.getType().hasName("sock *")
and vsk_760.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
