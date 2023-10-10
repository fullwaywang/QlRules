/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_resume
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/wcn36xx-resume
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_resume CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwcn_1142, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("enable_irq")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tx_irq"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_1142
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Variable vwcn_1142, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("enable_irq")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rx_irq"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_1142
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1))
}

predicate func_2(Variable vwcn_1142, Variable vvif_1143) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("wcn36xx_smd_arp_offload")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vwcn_1142
		and target_2.getArgument(1).(VariableAccess).getTarget()=vvif_1143)
}

from Function func, Variable vwcn_1142, Variable vvif_1143
where
not func_0(vwcn_1142, func)
and not func_1(vwcn_1142, func)
and vwcn_1142.getType().hasName("wcn36xx *")
and func_2(vwcn_1142, vvif_1143)
and vvif_1143.getType().hasName("ieee80211_vif *")
and vwcn_1142.getParentScope+() = func
and vvif_1143.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
