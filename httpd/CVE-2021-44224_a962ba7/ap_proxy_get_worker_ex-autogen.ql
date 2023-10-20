/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-ap_proxy_get_worker_ex
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/ap-proxy-get-worker-ex
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-modules/proxy/proxy_util.c-ap_proxy_get_worker_ex CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vurl_1727, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vurl_1727
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vurl_1727, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vurl_1727
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_proxy_de_socketfy")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("apr_pool_t *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vurl_1727
}

predicate func_2(Parameter vurl_1727, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strchr")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vurl_1727
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="58"
}

from Function func, Parameter vurl_1727, ExprStmt target_1, ExprStmt target_2
where
not func_0(vurl_1727, target_1, target_2, func)
and func_1(vurl_1727, target_1)
and func_2(vurl_1727, target_2)
and vurl_1727.getType().hasName("const char *")
and vurl_1727.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
