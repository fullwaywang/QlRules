/**
 * @name curl-b27ad8e1d3e68e-create_conn
 * @id cpp/curl/b27ad8e1d3e68e/create-conn
 * @description curl-b27ad8e1d3e68e-lib/url.c-create_conn CVE-2022-27779
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_3596, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("strip_trailing_dot")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="host"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3596
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Variable vconn_3596, Function func, IfStmt target_1) {
		target_1.getCondition().(ValueFieldAccess).getTarget().getName()="httpproxy"
		and target_1.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_1.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3596
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strip_trailing_dot")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="host"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3596
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vconn_3596, Function func, IfStmt target_2) {
		target_2.getCondition().(ValueFieldAccess).getTarget().getName()="socksproxy"
		and target_2.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_2.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3596
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strip_trailing_dot")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="host"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="socks_proxy"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3596
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vconn_3596, Function func, IfStmt target_3) {
		target_3.getCondition().(ValueFieldAccess).getTarget().getName()="conn_to_host"
		and target_3.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_3.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3596
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strip_trailing_dot")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="conn_to_host"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3596
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

from Function func, Variable vconn_3596, ExprStmt target_0, IfStmt target_1, IfStmt target_2, IfStmt target_3
where
func_0(vconn_3596, func, target_0)
and func_1(vconn_3596, func, target_1)
and func_2(vconn_3596, func, target_2)
and func_3(vconn_3596, func, target_3)
and vconn_3596.getType().hasName("connectdata *")
and vconn_3596.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
