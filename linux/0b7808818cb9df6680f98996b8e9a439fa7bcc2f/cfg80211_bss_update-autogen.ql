/**
 * @name linux-0b7808818cb9df6680f98996b8e9a439fa7bcc2f-cfg80211_bss_update
 * @id cpp/linux/0b7808818cb9df6680f98996b8e9a439fa7bcc2f/cfg80211_bss_update
 * @description linux-0b7808818cb9df6680f98996b8e9a439fa7bcc2f-cfg80211_bss_update CVE-2022-42720
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vfound_1700, Variable vnew_1720) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="transmitted_bss"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_1720
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vfound_1700)
}

predicate func_1(Variable vnew_1720) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="pub"
		and target_1.getQualifier().(VariableAccess).getTarget()=vnew_1720)
}

from Function func, Variable vfound_1700, Variable vnew_1720
where
not func_0(vfound_1700, vnew_1720)
and vfound_1700.getType().hasName("cfg80211_internal_bss *")
and vnew_1720.getType().hasName("cfg80211_internal_bss *")
and func_1(vnew_1720)
and vfound_1700.getParentScope+() = func
and vnew_1720.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
