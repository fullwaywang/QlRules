/**
 * @name curl-13c9a9ded3ae744a1e11cbc14e9146d9fa427040-imap_state_fetch_resp
 * @id cpp/curl/13c9a9ded3ae744a1e11cbc14e9146d9fa427040/imap-state-fetch-resp
 * @description curl-13c9a9ded3ae744a1e11cbc14e9146d9fa427040-lib/imap.c-imap_state_fetch_resp CVE-2017-1000257
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vchunk_1123, PointerFieldAccess target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vchunk_1123
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vconn_1081, ExprStmt target_6, ExprStmt target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("state")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1081
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_1)
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vconn_1081, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("state")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1081
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(PointerFieldAccess target_3) {
		target_3.getTarget().getName()="cache"
}

predicate func_4(Variable vchunk_1123, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchunk_1123
}

predicate func_5(Parameter vconn_1081, Variable vchunk_1123, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_client_write")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1081
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="1"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="cache"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vchunk_1123
}

predicate func_6(Parameter vconn_1081, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("Curl_setup_transfer")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1081
		and target_6.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(5).(UnaryMinusExpr).getValue()="-1"
		and target_6.getExpr().(FunctionCall).getArgument(6).(Literal).getValue()="0"
}

from Function func, Parameter vconn_1081, Variable vchunk_1123, ExprStmt target_2, PointerFieldAccess target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vchunk_1123, target_3, target_4, target_5)
and not func_1(vconn_1081, target_6, target_2, func)
and func_2(vconn_1081, func, target_2)
and func_3(target_3)
and func_4(vchunk_1123, target_4)
and func_5(vconn_1081, vchunk_1123, target_5)
and func_6(vconn_1081, target_6)
and vconn_1081.getType().hasName("connectdata *")
and vchunk_1123.getType().hasName("size_t")
and vconn_1081.getParentScope+() = func
and vchunk_1123.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
