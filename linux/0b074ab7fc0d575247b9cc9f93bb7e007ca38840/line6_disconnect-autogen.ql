/**
 * @name linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-line6_disconnect
 * @id cpp/linux/0b074ab7fc0d575247b9cc9f93bb7e007ca38840/line6-disconnect
 * @description linux-0b074ab7fc0d575247b9cc9f93bb7e007ca38840-line6_disconnect 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vline6_819, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("cancel_delayed_work")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="startup_work"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vline6_819
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Variable vline6_819) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="usbdev"
		and target_1.getQualifier().(VariableAccess).getTarget()=vline6_819)
}

from Function func, Variable vline6_819
where
not func_0(vline6_819, func)
and vline6_819.getType().hasName("usb_line6 *")
and func_1(vline6_819)
and vline6_819.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
