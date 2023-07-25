/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-add_member
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/add-member
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-modules/proxy/mod_proxy.c-add_member CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
		and target_0.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue() instanceof FunctionCall
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(StringLiteral).getValue()="BalancerMember uses an invalid \"unix:\" URL"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0))
}

predicate func_2(Parameter vcmd_2629, Variable vname_2637, FunctionCall target_2) {
		target_2.getTarget().hasName("ap_proxy_de_socketfy")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="temp_pool"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2629
		and target_2.getArgument(1).(VariableAccess).getTarget()=vname_2637
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_proxy_get_worker")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="temp_pool"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2629
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("proxy_balancer *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("proxy_server_conf *")
}

from Function func, Parameter vcmd_2629, Variable vname_2637, FunctionCall target_2
where
not func_0(func)
and func_2(vcmd_2629, vname_2637, target_2)
and vcmd_2629.getType().hasName("cmd_parms *")
and vname_2637.getType().hasName("char *")
and vcmd_2629.getFunction() = func
and vname_2637.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
