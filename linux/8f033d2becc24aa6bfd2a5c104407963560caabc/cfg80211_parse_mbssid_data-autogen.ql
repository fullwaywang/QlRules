/**
 * @name linux-8f033d2becc24aa6bfd2a5c104407963560caabc-cfg80211_parse_mbssid_data
 * @id cpp/linux/8f033d2becc24aa6bfd2a5c104407963560caabc/cfg80211_parse_mbssid_data
 * @description linux-8f033d2becc24aa6bfd2a5c104407963560caabc-cfg80211_parse_mbssid_data CVE-2022-41674
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable velem_2117) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_2117
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_2117
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_0.getThen().(ContinueStmt).toString() = "continue;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_2117)
}

predicate func_1(Variable velem_2117) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="datalen"
		and target_1.getQualifier().(VariableAccess).getTarget()=velem_2117)
}

from Function func, Variable velem_2117
where
not func_0(velem_2117)
and velem_2117.getType().hasName("const element *")
and func_1(velem_2117)
and velem_2117.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
