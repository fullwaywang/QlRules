/**
 * @name linux-5c455c5ab332773464d02ba17015acdca198f03d-mwifiex_cmd_802_11_ad_hoc_start
 * @id cpp/linux/5c455c5ab332773464d02ba17015acdca198f03d/mwifiex-cmd-802-11-ad-hoc-start
 * @description linux-5c455c5ab332773464d02ba17015acdca198f03d-mwifiex_cmd_802_11_ad_hoc_start 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vreq_ssid_842, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ssid_len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_ssid_842
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ssid_len"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_ssid_842
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="32"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0))
}

from Function func, Parameter vreq_ssid_842
where
not func_0(vreq_ssid_842, func)
and vreq_ssid_842.getType().hasName("cfg80211_ssid *")
and vreq_ssid_842.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
