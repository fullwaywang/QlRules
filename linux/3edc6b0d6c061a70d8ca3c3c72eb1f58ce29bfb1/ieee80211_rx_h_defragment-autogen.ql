/**
 * @name linux-3edc6b0d6c061a70d8ca3c3c72eb1f58ce29bfb1-ieee80211_rx_h_defragment
 * @id cpp/linux/3edc6b0d6c061a70d8ca3c3c72eb1f58ce29bfb1/ieee80211_rx_h_defragment
 * @description linux-3edc6b0d6c061a70d8ca3c3c72eb1f58ce29bfb1-ieee80211_rx_h_defragment CVE-2020-24586
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vrx_2223, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("IEEE80211_SKB_RXCB")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="skb"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_2223
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_0)
}

predicate func_1(Function func) {
	exists(BitwiseAndExpr target_1 |
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flag"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ieee80211_rx_status *")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vrx_2223, Variable ventry_2230) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="key"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_2223
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flag"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ieee80211_rx_status *")
		and target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="is_protected"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_2230
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_4(Parameter vrx_2223, Variable ventry_2230) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="is_protected"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_2230
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="key"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_2223
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="key_color"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_2230
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="key"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_2223
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flag"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ieee80211_rx_status *")
		and target_4.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_4.getParent().(IfStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="check_sequential_pn"
		and target_4.getParent().(IfStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_2230)
}

predicate func_6(Variable vfc_2228) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("ieee80211_has_protected")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vfc_2228)
}

predicate func_7(Variable vfc_2228) {
	exists(NotExpr target_7 |
		target_7.getOperand().(FunctionCall).getTarget().hasName("ieee80211_has_protected")
		and target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfc_2228)
}

predicate func_8(Parameter vrx_2223, Variable ventry_2230) {
	exists(EqualityOperation target_8 |
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="color"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="key"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_2223
		and target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="key_color"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_2230)
}

predicate func_9(Parameter vrx_2223) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="sdata"
		and target_9.getQualifier().(VariableAccess).getTarget()=vrx_2223)
}

predicate func_10(Parameter vrx_2223) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="key"
		and target_10.getQualifier().(VariableAccess).getTarget()=vrx_2223)
}

predicate func_11(Variable ventry_2230) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="key_color"
		and target_11.getQualifier().(VariableAccess).getTarget()=ventry_2230)
}

from Function func, Parameter vrx_2223, Variable vfc_2228, Variable ventry_2230
where
not func_0(vrx_2223, func)
and not func_1(func)
and not func_2(vrx_2223, ventry_2230)
and not func_4(vrx_2223, ventry_2230)
and func_6(vfc_2228)
and func_7(vfc_2228)
and func_8(vrx_2223, ventry_2230)
and vrx_2223.getType().hasName("ieee80211_rx_data *")
and func_9(vrx_2223)
and func_10(vrx_2223)
and vfc_2228.getType().hasName("__le16")
and ventry_2230.getType().hasName("ieee80211_fragment_entry *")
and func_11(ventry_2230)
and vrx_2223.getParentScope+() = func
and vfc_2228.getParentScope+() = func
and ventry_2230.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
