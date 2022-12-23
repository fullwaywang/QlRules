/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_suspend
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/wcn36xx-suspend
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_suspend CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwcn_1111, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("disable_irq")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tx_irq"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_1111
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Variable vwcn_1111, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("disable_irq")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rx_irq"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_1111
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_2(Variable vwcn_1111) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("wcn36xx_smd_wlan_host_suspend_ind")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vwcn_1111)
}

from Function func, Variable vwcn_1111
where
not func_0(vwcn_1111, func)
and not func_1(vwcn_1111, func)
and vwcn_1111.getType().hasName("wcn36xx *")
and func_2(vwcn_1111)
and vwcn_1111.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
