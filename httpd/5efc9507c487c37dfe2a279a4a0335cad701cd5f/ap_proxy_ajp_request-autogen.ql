/**
 * @name httpd-5efc9507c487c37dfe2a279a4a0335cad701cd5f-ap_proxy_ajp_request
 * @id cpp/httpd/5efc9507c487c37dfe2a279a4a0335cad701cd5f/ap-proxy-ajp-request
 * @description httpd-5efc9507c487c37dfe2a279a4a0335cad701cd5f-ap_proxy_ajp_request CVE-2022-36760
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_158, EqualityOperation target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="close"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_158
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Function func, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmp")
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunked"
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vconn_158, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="close"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_158
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vconn_158, EqualityOperation target_1, ExprStmt target_2
where
not func_0(vconn_158, target_1, target_2)
and func_1(func, target_1)
and func_2(vconn_158, target_2)
and vconn_158.getType().hasName("proxy_conn_rec *")
and vconn_158.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
