/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-proxysection
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/proxysection
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-proxysection CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(FunctionCall target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
		and target_0.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue() instanceof FunctionCall
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(StringLiteral).getValue()="<Proxy/ProxyMatch > uses an invalid \"unix:\" URL"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Variable vconf_2841, Parameter vcmd_2835, FunctionCall target_2) {
		target_2.getTarget().hasName("ap_proxy_de_socketfy")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="temp_pool"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2835
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="p"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_2841
}

predicate func_3(Variable vconf_2841, FunctionCall target_3) {
		target_3.getTarget().hasName("ap_proxy_valid_balancer_name")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="p"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_2841
		and target_3.getArgument(1).(Literal).getValue()="9"
}

from Function func, Variable vconf_2841, Parameter vcmd_2835, FunctionCall target_2, FunctionCall target_3
where
not func_0(target_3, func)
and func_2(vconf_2841, vcmd_2835, target_2)
and func_3(vconf_2841, target_3)
and vconf_2841.getType().hasName("proxy_dir_conf *")
and vcmd_2835.getType().hasName("cmd_parms *")
and vconf_2841.getParentScope+() = func
and vcmd_2835.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
