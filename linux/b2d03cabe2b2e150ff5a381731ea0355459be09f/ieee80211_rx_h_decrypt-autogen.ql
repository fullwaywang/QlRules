/**
 * @name linux-b2d03cabe2b2e150ff5a381731ea0355459be09f-ieee80211_rx_h_decrypt
 * @id cpp/linux/b2d03cabe2b2e150ff5a381731ea0355459be09f/ieee80211_rx_h_decrypt
 * @description linux-b2d03cabe2b2e150ff5a381731ea0355459be09f-ieee80211_rx_h_decrypt CVE-2022-42722
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vskb_1902, Parameter vrx_1900, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sdata"
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_1900
		and target_1.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cfg80211_rx_unprot_mlme_mgmt")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sdata"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_1900
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_1902
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="len"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_1902
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_1))
}

predicate func_3(Variable vskb_1902, Variable vmmie_keyidx_1909, Parameter vrx_1900) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("cfg80211_rx_unprot_mlme_mgmt")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sdata"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_1900
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_1902
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="len"
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_1902
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmmie_keyidx_1909
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmmie_keyidx_1909
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="2")
}

predicate func_4(Variable vresult_1906, Variable vfc_1910) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(FunctionCall).getTarget().hasName("ieee80211_is_beacon")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfc_1910
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresult_1906
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1")
}

predicate func_5(Parameter vrx_1900) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ieee80211_crypto_gcmp_decrypt")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vrx_1900)
}

from Function func, Variable vskb_1902, Variable vresult_1906, Variable vmmie_keyidx_1909, Variable vfc_1910, Parameter vrx_1900
where
not func_1(vskb_1902, vrx_1900, func)
and func_3(vskb_1902, vmmie_keyidx_1909, vrx_1900)
and func_4(vresult_1906, vfc_1910)
and vskb_1902.getType().hasName("sk_buff *")
and vresult_1906.getType().hasName("ieee80211_rx_result")
and vmmie_keyidx_1909.getType().hasName("int")
and vfc_1910.getType().hasName("__le16")
and vrx_1900.getType().hasName("ieee80211_rx_data *")
and func_5(vrx_1900)
and vskb_1902.getParentScope+() = func
and vresult_1906.getParentScope+() = func
and vmmie_keyidx_1909.getParentScope+() = func
and vfc_1910.getParentScope+() = func
and vrx_1900.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
