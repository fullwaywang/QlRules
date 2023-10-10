/**
 * @name linux-5c4c8c9544099bb9043a10a5318130a943e32fc3-hci_disconn_loglink_complete_evt
 * @id cpp/linux/5c4c8c9544099bb9043a10a5318130a943e32fc3/hci-disconn-loglink-complete-evt
 * @description linux-5c4c8c9544099bb9043a10a5318130a943e32fc3-hci_disconn_loglink_complete_evt 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhchan_5056) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="amp"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhchan_5056
		and target_0.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_1(Variable vhchan_5056) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vhchan_5056
		and target_1.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_2(Variable vev_5055, Variable vhchan_5056, Parameter vhdev_5052) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vhchan_5056
		and target_2.getRValue().(FunctionCall).getTarget().hasName("hci_chan_lookup_handle")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_5052
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="handle"
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vev_5055)
}

from Function func, Variable vev_5055, Variable vhchan_5056, Parameter vhdev_5052
where
not func_0(vhchan_5056)
and func_1(vhchan_5056)
and vhchan_5056.getType().hasName("hci_chan *")
and func_2(vev_5055, vhchan_5056, vhdev_5052)
and vhdev_5052.getType().hasName("hci_dev *")
and vev_5055.getParentScope+() = func
and vhchan_5056.getParentScope+() = func
and vhdev_5052.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
