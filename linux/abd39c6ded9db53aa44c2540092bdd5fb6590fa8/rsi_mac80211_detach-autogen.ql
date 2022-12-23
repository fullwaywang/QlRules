/**
 * @name linux-abd39c6ded9db53aa44c2540092bdd5fb6590fa8-rsi_mac80211_detach
 * @id cpp/linux/abd39c6ded9db53aa44c2540092bdd5fb6590fa8/rsi_mac80211_detach
 * @description linux-abd39c6ded9db53aa44c2540092bdd5fb6590fa8-rsi_mac80211_detach 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vhw_241, Parameter vadapter_239) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hw"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_239
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vhw_241)
}

predicate func_1(Parameter vadapter_239) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="hw"
		and target_1.getQualifier().(VariableAccess).getTarget()=vadapter_239)
}

from Function func, Variable vhw_241, Parameter vadapter_239
where
not func_0(vhw_241, vadapter_239)
and vhw_241.getType().hasName("ieee80211_hw *")
and vadapter_239.getType().hasName("rsi_hw *")
and func_1(vadapter_239)
and vhw_241.getParentScope+() = func
and vadapter_239.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
