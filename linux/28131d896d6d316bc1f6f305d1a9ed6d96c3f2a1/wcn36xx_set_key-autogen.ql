/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_set_key
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/wcn36xx-set-key
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_set_key CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvif_519, Variable vvif_priv_524) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_519
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="allow_bmps"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_priv_524)
}

from Function func, Parameter vvif_519, Variable vvif_priv_524
where
func_0(vvif_519, vvif_priv_524)
and vvif_519.getType().hasName("ieee80211_vif *")
and vvif_priv_524.getType().hasName("wcn36xx_vif *")
and vvif_519.getParentScope+() = func
and vvif_priv_524.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
