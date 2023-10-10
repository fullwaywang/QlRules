/**
 * @name linux-40e7462dad6f3d06efdb17d26539e61ab6e34db1-ath10k_htt_rx_proc_rx_frag_ind_hl
 * @id cpp/linux/40e7462dad6f3d06efdb17d26539e61ab6e34db1/ath10k_htt_rx_proc_rx_frag_ind_hl
 * @description linux-40e7462dad6f3d06efdb17d26539e61ab6e34db1-ath10k_htt_rx_proc_rx_frag_ind_hl CVE-2020-26145
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vhdr_2586, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("is_multicast_ether_addr")
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="addr1"
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_2586
		and target_0.getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_0))
}

from Function func, Variable vhdr_2586
where
not func_0(vhdr_2586, func)
and vhdr_2586.getType().hasName("ieee80211_hdr *")
and vhdr_2586.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
