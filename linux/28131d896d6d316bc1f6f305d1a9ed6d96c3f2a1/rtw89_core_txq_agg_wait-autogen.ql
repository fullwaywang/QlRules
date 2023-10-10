/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rtw89_core_txq_agg_wait
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rtw89-core-txq-agg-wait
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rtw89_core_txq_agg_wait CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsta_1536) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vsta_1536
		and target_0.getThen() instanceof PointerFieldAccess
		and target_0.getElse().(Literal).getValue()="0")
}

predicate func_1(Variable vsta_1536) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="drv_priv"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsta_1536)
}

from Function func, Variable vsta_1536
where
not func_0(vsta_1536)
and func_1(vsta_1536)
and vsta_1536.getType().hasName("ieee80211_sta *")
and vsta_1536.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
