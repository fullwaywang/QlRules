/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_probe
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/wcn36xx-probe
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_probe CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SizeofTypeOperator target_0 |
		target_0.getType() instanceof LongType
		and target_0.getValue()="1912"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vwcn_1479, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("__skb_queue_head_init")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="amsdu"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_1479
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_1))
}

predicate func_2(Variable vwcn_1479) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="scan_lock"
		and target_2.getQualifier().(VariableAccess).getTarget()=vwcn_1479)
}

from Function func, Variable vwcn_1479
where
func_0(func)
and not func_1(vwcn_1479, func)
and vwcn_1479.getType().hasName("wcn36xx *")
and func_2(vwcn_1479)
and vwcn_1479.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
