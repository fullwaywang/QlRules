/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_update_last_rssi
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rs-update-last-rssi
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_update_last_rssi CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlq_sta_2649) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="chain_signal"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="pers"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlq_sta_2649)
}

predicate func_1(Parameter vrx_status_2647, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase() instanceof ValueFieldAccess
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="chain_signal"
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_status_2647
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vrx_status_2647, Variable vlq_sta_2649
where
func_0(vlq_sta_2649)
and func_1(vrx_status_2647, func)
and vrx_status_2647.getType().hasName("ieee80211_rx_status *")
and vlq_sta_2649.getType().hasName("iwl_lq_sta *")
and vrx_status_2647.getParentScope+() = func
and vlq_sta_2649.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
