/**
 * @name curl-13c9a9ded3ae744a1e11cbc14e9146d9fa427040-imap_state_fetch_resp
 * @id cpp/curl/13c9a9ded3ae744a1e11cbc14e9146d9fa427040/imap-state-fetch-resp
 * @description curl-13c9a9ded3ae744a1e11cbc14e9146d9fa427040-lib/imap.c-imap_state_fetch_resp CVE-2017-1000257
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_1081, Variable vchunk_1123, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vchunk_1123
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("state")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1081
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(PointerFieldAccess target_1) {
		target_1.getTarget().getName()="cache"
		and target_1.getQualifier().(VariableAccess).getTarget().getType().hasName("pingpong *")
}

predicate func_2(Parameter vconn_1081, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("state")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1081
}

predicate func_3(Parameter vconn_1081, Variable vchunk_1123, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("CURLcode")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_client_write")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1081
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="cache"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("pingpong *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vchunk_1123
}

predicate func_4(Variable vchunk_1123, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchunk_1123
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("curl_off_t")
}

from Function func, Parameter vconn_1081, Variable vchunk_1123, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vconn_1081, vchunk_1123, target_1, target_2, target_3, target_4)
and func_1(target_1)
and func_2(vconn_1081, target_2)
and func_3(vconn_1081, vchunk_1123, target_3)
and func_4(vchunk_1123, target_4)
and vconn_1081.getType().hasName("connectdata *")
and vchunk_1123.getType().hasName("size_t")
and vconn_1081.getFunction() = func
and vchunk_1123.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
