/**
 * @name httpd-8b6d55f6a047acf62675e32606b037f5eea8ccc7-ap_proxy_http_process_response
 * @id cpp/httpd/8b6d55f6a047acf62675e32606b037f5eea8ccc7/ap-proxy-http-process-response
 * @description httpd-8b6d55f6a047acf62675e32606b037f5eea8ccc7-modules/proxy/mod_proxy_http.c-ap_proxy_http_process_response CVE-2022-37436
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_1065, LogicalAndExpr target_4) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vrc_1065
		and target_0.getRValue() instanceof FunctionCall
		and target_4.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrc_1065, BlockStmt target_5) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_1065
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(IfStmt).getThen()=target_5)
}

predicate func_2(Variable vr_988, BlockStmt target_5, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="headers_out"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_988
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_5
}

predicate func_3(Variable vr_988, Variable vbackend_991, Variable vorigin_992, Variable vbuffer_996, Variable vresponse_field_size_1006, Variable vpread_len_1007, FunctionCall target_3) {
		target_3.getTarget().hasName("ap_proxy_read_headers")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vr_988
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="r"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_991
		and target_3.getArgument(2).(VariableAccess).getTarget()=vbuffer_996
		and target_3.getArgument(3).(VariableAccess).getTarget()=vresponse_field_size_1006
		and target_3.getArgument(4).(VariableAccess).getTarget()=vorigin_992
		and target_3.getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpread_len_1007
}

predicate func_4(Variable vr_988, Variable vrc_1065, LogicalAndExpr target_4) {
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="proxyreq"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_988
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="keepalives"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("conn_rec *")
		and target_4.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_1065
		and target_4.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(AddExpr).getValue()="70007"
}

predicate func_5(Variable vr_988, BlockStmt target_5) {
		target_5.getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getValue()="1"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="4"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vr_988
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="AH01106: bad HTTP/%d.%d header returned by %s (%s)"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="uri"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(PointerFieldAccess).getTarget().getName()="method"
}

from Function func, Variable vr_988, Variable vbackend_991, Variable vorigin_992, Variable vbuffer_996, Variable vresponse_field_size_1006, Variable vpread_len_1007, Variable vrc_1065, EqualityOperation target_2, FunctionCall target_3, LogicalAndExpr target_4, BlockStmt target_5
where
not func_0(vrc_1065, target_4)
and not func_1(vrc_1065, target_5)
and func_2(vr_988, target_5, target_2)
and func_3(vr_988, vbackend_991, vorigin_992, vbuffer_996, vresponse_field_size_1006, vpread_len_1007, target_3)
and func_4(vr_988, vrc_1065, target_4)
and func_5(vr_988, target_5)
and vr_988.getType().hasName("request_rec *")
and vbackend_991.getType().hasName("proxy_conn_rec *")
and vorigin_992.getType().hasName("conn_rec *")
and vbuffer_996.getType().hasName("char *")
and vresponse_field_size_1006.getType().hasName("apr_size_t")
and vpread_len_1007.getType().hasName("int")
and vrc_1065.getType().hasName("apr_status_t")
and vr_988.(LocalVariable).getFunction() = func
and vbackend_991.(LocalVariable).getFunction() = func
and vorigin_992.(LocalVariable).getFunction() = func
and vbuffer_996.(LocalVariable).getFunction() = func
and vresponse_field_size_1006.(LocalVariable).getFunction() = func
and vpread_len_1007.(LocalVariable).getFunction() = func
and vrc_1065.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
