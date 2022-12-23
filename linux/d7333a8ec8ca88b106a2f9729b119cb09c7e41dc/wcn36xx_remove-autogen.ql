/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_remove
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/wcn36xx-remove
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_remove CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwcn_1564, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__skb_queue_purge")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="amsdu"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_1564
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_1(Variable vwcn_1564) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="ccu_base"
		and target_1.getQualifier().(VariableAccess).getTarget()=vwcn_1564)
}

from Function func, Variable vwcn_1564
where
not func_0(vwcn_1564, func)
and vwcn_1564.getType().hasName("wcn36xx *")
and func_1(vwcn_1564)
and vwcn_1564.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
