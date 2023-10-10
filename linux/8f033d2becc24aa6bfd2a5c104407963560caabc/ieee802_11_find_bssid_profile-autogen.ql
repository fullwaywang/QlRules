/**
 * @name linux-8f033d2becc24aa6bfd2a5c104407963560caabc-ieee802_11_find_bssid_profile
 * @id cpp/linux/8f033d2becc24aa6bfd2a5c104407963560caabc/ieee802_11_find_bssid_profile
 * @description linux-8f033d2becc24aa6bfd2a5c104407963560caabc-ieee802_11_find_bssid_profile CVE-2022-41674
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable velem_1438) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_1438
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_1438
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_0.getThen().(ContinueStmt).toString() = "continue;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_1438)
}

predicate func_1(Variable velem_1438) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="datalen"
		and target_1.getQualifier().(VariableAccess).getTarget()=velem_1438)
}

from Function func, Variable velem_1438
where
not func_0(velem_1438)
and velem_1438.getType().hasName("const element *")
and func_1(velem_1438)
and velem_1438.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
