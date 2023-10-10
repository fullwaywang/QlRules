/**
 * @name httpd-d93e61e3e9622bacff746772cb9c97fdcaed8baf-ap_proxy_ajp_request
 * @id cpp/httpd/d93e61e3e9622bacff746772cb9c97fdcaed8baf/ap-proxy-ajp-request
 * @description httpd-d93e61e3e9622bacff746772cb9c97fdcaed8baf-modules/proxy/mod_proxy_ajp.c-ap_proxy_ajp_request CVE-2022-36760
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_158, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="close"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_158
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmp")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunked"
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vconn_158, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="close"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_158
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_3(Parameter vconn_158, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="close"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_158
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vconn_158, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vconn_158, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vconn_158, target_2)
and func_3(vconn_158, target_3)
and vconn_158.getType().hasName("proxy_conn_rec *")
and vconn_158.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
