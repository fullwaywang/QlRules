/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_init_ieee80211
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/wcn36xx-init-ieee80211
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_init_ieee80211 CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwcn_1334) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="hw"
		and target_0.getQualifier().(VariableAccess).getTarget()=vwcn_1334
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("_ieee80211_hw_set")
		and target_1.getExpr().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vwcn_1334
where
func_0(vwcn_1334)
and func_1(func)
and vwcn_1334.getType().hasName("wcn36xx *")
and vwcn_1334.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
