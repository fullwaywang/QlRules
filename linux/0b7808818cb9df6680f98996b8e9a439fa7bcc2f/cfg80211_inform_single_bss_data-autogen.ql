/**
 * @name linux-0b7808818cb9df6680f98996b8e9a439fa7bcc2f-cfg80211_inform_single_bss_data
 * @id cpp/linux/0b7808818cb9df6680f98996b8e9a439fa7bcc2f/cfg80211_inform_single_bss_data
 * @description linux-0b7808818cb9df6680f98996b8e9a439fa7bcc2f-cfg80211_inform_single_bss_data CVE-2022-42720
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable v__flags_1944) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(0) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(2).(VariableAccess).getTarget()=v__flags_1944
		and target_0.getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getStmt().(BlockStmt).getStmt(0).(AsmStmt).getChild(3).(SizeofTypeOperator).getValue()="12")
}

predicate func_2(Variable vrdev_1936, Variable vres_1939) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_1939
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__cfg80211_unlink_bss")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdev_1936
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vres_1939)
}

predicate func_3(Parameter vnon_tx_data_1933, Variable vres_1939) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vres_1939
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnon_tx_data_1933)
}

predicate func_4(Variable vrdev_1936, Variable vres_1939) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="bss_generation"
		and target_4.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdev_1936
		and target_4.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__cfg80211_unlink_bss")
		and target_4.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdev_1936
		and target_4.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vres_1939)
}

from Function func, Parameter vnon_tx_data_1933, Variable vrdev_1936, Variable vres_1939, Variable v__flags_1944
where
not func_0(v__flags_1944)
and not func_2(vrdev_1936, vres_1939)
and not func_3(vnon_tx_data_1933, vres_1939)
and func_4(vrdev_1936, vres_1939)
and vnon_tx_data_1933.getType().hasName("cfg80211_non_tx_bss *")
and vrdev_1936.getType().hasName("cfg80211_registered_device *")
and vres_1939.getType().hasName("cfg80211_internal_bss *")
and v__flags_1944.getType().hasName("int")
and vnon_tx_data_1933.getParentScope+() = func
and vrdev_1936.getParentScope+() = func
and vres_1939.getParentScope+() = func
and v__flags_1944.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
