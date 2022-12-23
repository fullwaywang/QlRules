/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_bss_info_changed
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/wcn36xx-bss-info-changed
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_bss_info_changed CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvif_priv_826, Parameter vbss_conf_819) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="allow_bmps"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_priv_826
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="assoc"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbss_conf_819)
}

from Function func, Variable vvif_priv_826, Parameter vbss_conf_819
where
func_0(vvif_priv_826, vbss_conf_819)
and vvif_priv_826.getType().hasName("wcn36xx_vif *")
and vbss_conf_819.getType().hasName("ieee80211_bss_conf *")
and vvif_priv_826.getParentScope+() = func
and vbss_conf_819.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
