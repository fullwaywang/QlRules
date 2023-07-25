/**
 * @name curl-75dc096e01ef1e21b6c57690d99371dedb2c0b80-close_all_connections
 * @id cpp/curl/75dc096e01ef1e21b6c57690d99371dedb2c0b80/close-all-connections
 * @description curl-75dc096e01ef1e21b6c57690d99371dedb2c0b80-lib/multi.c-close_all_connections CVE-2016-5421
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_2152, ExprStmt target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="easy_conn"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2152
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vconn_2152, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("sigpipe_ignore")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2152
}

predicate func_2(Variable vconn_2152, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("Curl_disconnect")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_2152
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Variable vconn_2152, ExprStmt target_1, ExprStmt target_2
where
not func_0(vconn_2152, target_1, target_2)
and func_1(vconn_2152, target_1)
and func_2(vconn_2152, target_2)
and vconn_2152.getType().hasName("connectdata *")
and vconn_2152.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
