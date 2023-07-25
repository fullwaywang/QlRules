/**
 * @name curl-53bcf55b4538067e6-create_conn
 * @id cpp/curl/53bcf55b4538067e6/create-conn
 * @description curl-53bcf55b4538067e6-create_conn CVE-2022-42916
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_3609) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="host"
		and target_0.getQualifier().(VariableAccess).getTarget()=vconn_3609)
}

predicate func_2(Variable vconn_3609) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="conn_to_host"
		and target_2.getQualifier().(VariableAccess).getTarget()=vconn_3609)
}

predicate func_3(Variable vresult_3608, Variable vconn_3609) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vresult_3608
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ValueFieldAccess).getTarget().getName()="conn_to_host"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3609)
}

predicate func_5(Variable vconn_3609) {
	exists(ValueFieldAccess target_5 |
		target_5.getTarget().getName()="host"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3609)
}

predicate func_7(Variable vconn_3609) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="bits"
		and target_7.getQualifier().(VariableAccess).getTarget()=vconn_3609
		and target_7.getParent().(ValueFieldAccess).getParent().(IfStmt).getThen() instanceof BlockStmt)
}

predicate func_8(Variable vconn_3609) {
	exists(ValueFieldAccess target_8 |
		target_8.getTarget().getName()="host"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="socks_proxy"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3609)
}

predicate func_10(Variable vresult_3608, Parameter vdata_3604, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3608
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_idnconvert_hostname")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_3604
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand() instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Variable vresult_3608, Parameter vdata_3604, Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition() instanceof ValueFieldAccess
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3608
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_idnconvert_hostname")
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_3604
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand() instanceof PointerFieldAccess
		and target_11.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_13(Variable vresult_3608, Parameter vdata_3604, Function func) {
	exists(IfStmt target_13 |
		target_13.getCondition() instanceof ValueFieldAccess
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3608
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_idnconvert_hostname")
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_3604
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_13.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

predicate func_15(Variable vresult_3608, Parameter vdata_3604, Function func) {
	exists(IfStmt target_15 |
		target_15.getCondition().(ValueFieldAccess).getTarget().getName()="socksproxy"
		and target_15.getCondition().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3608
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_idnconvert_hostname")
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_3604
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_15.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15)
}

from Function func, Variable vresult_3608, Variable vconn_3609, Parameter vdata_3604
where
func_0(vconn_3609)
and func_2(vconn_3609)
and func_3(vresult_3608, vconn_3609)
and func_5(vconn_3609)
and func_7(vconn_3609)
and func_8(vconn_3609)
and func_10(vresult_3608, vdata_3604, func)
and func_11(vresult_3608, vdata_3604, func)
and func_13(vresult_3608, vdata_3604, func)
and func_15(vresult_3608, vdata_3604, func)
and vresult_3608.getType().hasName("CURLcode")
and vconn_3609.getType().hasName("connectdata *")
and vdata_3604.getType().hasName("Curl_easy *")
and vresult_3608.getParentScope+() = func
and vconn_3609.getParentScope+() = func
and vdata_3604.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
