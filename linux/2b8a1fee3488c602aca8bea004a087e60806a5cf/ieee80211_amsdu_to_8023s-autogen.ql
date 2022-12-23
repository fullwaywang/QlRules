/**
 * @name linux-2b8a1fee3488c602aca8bea004a087e60806a5cf-ieee80211_amsdu_to_8023s
 * @id cpp/linux/2b8a1fee3488c602aca8bea004a087e60806a5cf/ieee80211_amsdu_to_8023s
 * @description linux-2b8a1fee3488c602aca8bea004a087e60806a5cf-ieee80211_amsdu_to_8023s CVE-2020-24588
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable veth_755) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("ether_addr_equal")
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="h_dest"
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=veth_755
		and target_0.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const unsigned char[6]")
		and target_0.getThen().(GotoStmt).toString() = "goto ...")
}

from Function func, Variable veth_755
where
not func_0(veth_755)
and veth_755.getType().hasName("ethhdr")
and veth_755.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
