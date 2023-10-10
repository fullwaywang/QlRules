/**
 * @name linux-5c4c8c9544099bb9043a10a5318130a943e32fc3-hci_loglink_complete_evt
 * @id cpp/linux/5c4c8c9544099bb9043a10a5318130a943e32fc3/hci-loglink-complete-evt
 * @description linux-5c4c8c9544099bb9043a10a5318130a943e32fc3-hci_loglink_complete_evt 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhchan_5018, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="amp"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhchan_5018
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_1(Variable vhchan_5018) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="handle"
		and target_1.getQualifier().(VariableAccess).getTarget()=vhchan_5018)
}

from Function func, Variable vhchan_5018
where
not func_0(vhchan_5018, func)
and vhchan_5018.getType().hasName("hci_chan *")
and func_1(vhchan_5018)
and vhchan_5018.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
