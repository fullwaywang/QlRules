/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-internal_internal_redirect
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/internal-internal-redirect
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-modules/http/http_request.c-internal_internal_redirect CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_531, BlockStmt target_1, FunctionCall target_0) {
		target_0.getTarget().hasName("ap_run_post_read_request")
		and not target_0.getTarget().hasName("ap_post_read_request")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnew_531
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getParent().(AssignExpr).getParent().(IfStmt).getThen()=target_1
}

predicate func_1(Variable vnew_531, BlockStmt target_1) {
		target_1.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_die")
		and target_1.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_531
		and target_1.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

from Function func, Variable vnew_531, FunctionCall target_0, BlockStmt target_1
where
func_0(vnew_531, target_1, target_0)
and func_1(vnew_531, target_1)
and vnew_531.getType().hasName("request_rec *")
and vnew_531.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
