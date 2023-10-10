/**
 * @name nginx-c1be55f97211d38b69ac0c2027e6812ab8b1b94e-ngx_http_send_error_page
 * @id cpp/nginx/c1be55f97211d38b69ac0c2027e6812ab8b1b94e/ngx-http-send-error-page
 * @description nginx-c1be55f97211d38b69ac0c2027e6812ab8b1b94e-src/http/ngx_http_special_response.c-ngx_http_send_error_page CVE-2019-20372
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vr_584, FunctionCall target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="expect_tested"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_584
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vr_584, AddressOfExpr target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ngx_http_discard_request_body")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_584
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="keepalive"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_584
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vr_584, FunctionCall target_2) {
		target_2.getTarget().hasName("ngx_http_named_location")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vr_584
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("ngx_str_t")
}

predicate func_3(Parameter vr_584, AddressOfExpr target_3) {
		target_3.getOperand().(ValueFieldAccess).getTarget().getName()="headers"
		and target_3.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="headers_out"
		and target_3.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_584
}

from Function func, Parameter vr_584, FunctionCall target_2, AddressOfExpr target_3
where
not func_0(vr_584, target_2, func)
and not func_1(vr_584, target_3, func)
and func_2(vr_584, target_2)
and func_3(vr_584, target_3)
and vr_584.getType().hasName("ngx_http_request_t *")
and vr_584.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
