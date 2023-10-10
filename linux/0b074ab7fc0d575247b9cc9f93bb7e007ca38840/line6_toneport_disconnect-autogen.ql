/**
 * @name linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-line6_toneport_disconnect
 * @id cpp/linux/0b074ab7fc0d575247b9cc9f93bb7e007ca38840/line6-toneport-disconnect
 * @description linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-line6_toneport_disconnect 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtoneport_407, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("cancel_delayed_work_sync")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pcm_work"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtoneport_407
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Variable vtoneport_407
where
func_0(vtoneport_407, func)
and vtoneport_407.getType().hasName("usb_line6_toneport *")
and vtoneport_407.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
