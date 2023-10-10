/**
 * @name linux-e2cb6b891ad2b8caa9131e3be70f45243df82a80-hci_req_sync
 * @id cpp/linux/e2cb6b891ad2b8caa9131e3be70f45243df82a80/hci_req_sync
 * @description linux-e2cb6b891ad2b8caa9131e3be70f45243df82a80-hci_req_sync 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vret_273) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_273
		and target_0.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_0.getParent().(IfStmt).getCondition() instanceof FunctionCall)
}

predicate func_1(Parameter vhdev_269) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("test_bit")
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_269)
}

predicate func_2(Function func) {
	exists(UnaryMinusExpr target_2 |
		target_2.getValue()="-100"
		and target_2.getOperand().(Literal).getValue()="100"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vhdev_269, Parameter vreq_269, Parameter vopt_271, Parameter vtimeout_271, Parameter vhci_status_271, Variable vret_273, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_273
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__hci_req_sync")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_269
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vreq_269
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vopt_271
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtimeout_271
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhci_status_271
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

from Function func, Parameter vhdev_269, Parameter vreq_269, Parameter vopt_271, Parameter vtimeout_271, Parameter vhci_status_271, Variable vret_273
where
not func_0(vret_273)
and func_1(vhdev_269)
and func_2(func)
and func_3(vhdev_269, vreq_269, vopt_271, vtimeout_271, vhci_status_271, vret_273, func)
and vhdev_269.getType().hasName("hci_dev *")
and vreq_269.getType().hasName("..(*)(..)")
and vopt_271.getType().hasName("unsigned long")
and vtimeout_271.getType().hasName("u32")
and vhci_status_271.getType().hasName("u8 *")
and vret_273.getType().hasName("int")
and vhdev_269.getParentScope+() = func
and vreq_269.getParentScope+() = func
and vopt_271.getParentScope+() = func
and vtimeout_271.getParentScope+() = func
and vhci_status_271.getParentScope+() = func
and vret_273.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
