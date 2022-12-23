/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-if_usb_disconnect
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/if-usb-disconnect
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-if_usb_disconnect CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcardp_307, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcardp_307
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Variable vcardp_307) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("if_usb_free")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vcardp_307)
}

from Function func, Variable vcardp_307
where
not func_0(vcardp_307, func)
and vcardp_307.getType().hasName("if_usb_card *")
and func_1(vcardp_307)
and vcardp_307.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
