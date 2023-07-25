/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-set_proxy_param
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/set-proxy-param
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-modules/proxy/mod_proxy.c-set_proxy_param CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(FunctionCall target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
		and target_0.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue() instanceof FunctionCall
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(StringLiteral).getValue()="ProxySet uses an invalid \"unix:\" URL"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Variable vname_2736, Parameter vcmd_2731, FunctionCall target_2) {
		target_2.getTarget().hasName("ap_proxy_de_socketfy")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="temp_pool"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2731
		and target_2.getArgument(1).(VariableAccess).getTarget()=vname_2736
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_proxy_get_worker_ex")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="temp_pool"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2731
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("proxy_server_conf *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("unsigned int")
}

predicate func_3(Variable vname_2736, FunctionCall target_3) {
		target_3.getTarget().hasName("ap_proxy_valid_balancer_name")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vname_2736
		and target_3.getArgument(1).(Literal).getValue()="9"
}

from Function func, Variable vname_2736, Parameter vcmd_2731, FunctionCall target_2, FunctionCall target_3
where
not func_0(target_3, func)
and func_2(vname_2736, vcmd_2731, target_2)
and func_3(vname_2736, target_3)
and vname_2736.getType().hasName("char *")
and vcmd_2731.getType().hasName("cmd_parms *")
and vname_2736.(LocalVariable).getFunction() = func
and vcmd_2731.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
