/**
 * @name linux-f94b47c6bde624d6c07f43054087607c52054a95-rtw_alloc_hwxmits
 * @id cpp/linux/f94b47c6bde624d6c07f43054087607c52054a95/rtw-alloc-hwxmits
 * @description linux-f94b47c6bde624d6c07f43054087607c52054a95-rtw_alloc_hwxmits NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpxmitpriv_1471, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hwxmits"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpxmitpriv_1471
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_2(Variable vpxmitpriv_1471) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="hwxmit_entry"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpxmitpriv_1471)
}

from Function func, Variable vpxmitpriv_1471
where
not func_0(vpxmitpriv_1471, func)
and vpxmitpriv_1471.getType().hasName("xmit_priv *")
and func_2(vpxmitpriv_1471)
and vpxmitpriv_1471.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
