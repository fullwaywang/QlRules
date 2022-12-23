/**
 * @name linux-bcca852027e5878aec911a347407ecc88d6fff7f-cfg80211_add_nontrans_list
 * @id cpp/linux/bcca852027e5878aec911a347407ecc88d6fff7f/cfg80211_add_nontrans_list
 * @description linux-bcca852027e5878aec911a347407ecc88d6fff7f-cfg80211_add_nontrans_list CVE-2022-42721
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnontrans_bss_403, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("list_empty")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nontrans_list"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnontrans_bss_403
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vnontrans_bss_403) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="bssid"
		and target_1.getQualifier().(VariableAccess).getTarget()=vnontrans_bss_403)
}

from Function func, Parameter vnontrans_bss_403
where
not func_0(vnontrans_bss_403, func)
and vnontrans_bss_403.getType().hasName("cfg80211_bss *")
and func_1(vnontrans_bss_403)
and vnontrans_bss_403.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
