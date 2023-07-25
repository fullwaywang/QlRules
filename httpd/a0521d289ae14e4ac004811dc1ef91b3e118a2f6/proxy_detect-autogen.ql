/**
 * @name httpd-a0521d289ae14e4ac004811dc1ef91b3e118a2f6-proxy_detect
 * @id cpp/httpd/a0521d289ae14e4ac004811dc1ef91b3e118a2f6/proxy-detect
 * @description httpd-a0521d289ae14e4ac004811dc1ef91b3e118a2f6-modules/proxy/mod_proxy.c-proxy_detect CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vr_770, BlockStmt target_7) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand() instanceof ValueFieldAccess
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ap_matches_request_vhost")
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_770
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="hostname"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="port_str"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="port"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("ap_run_default_port")
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_770
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_7)
}

predicate func_1(Parameter vr_770, ValueFieldAccess target_8) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="parsed_uri"
		and target_1.getQualifier().(VariableAccess).getTarget()=vr_770
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vr_770, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="parsed_uri"
		and target_2.getQualifier().(VariableAccess).getTarget()=vr_770
}

*/
predicate func_3(Variable vconf_773, Parameter vr_770, BlockStmt target_9, LogicalAndExpr target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="req"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_773
		and target_3.getAnOperand().(ValueFieldAccess).getTarget().getName()="scheme"
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="hostname"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_9
}

/*predicate func_4(Parameter vr_770, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="hostname"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
}

*/
predicate func_5(Parameter vr_770, BlockStmt target_7, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmp")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="scheme"
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ap_run_http_scheme")
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_770
		and target_5.getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ap_matches_request_vhost")
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_770
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="hostname"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="port_str"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="port"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("ap_run_default_port")
		and target_5.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_770
		and target_5.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_6(Function func, LogicalAndExpr target_6) {
		target_6.getAnOperand() instanceof LogicalAndExpr
		and target_6.getAnOperand() instanceof ValueFieldAccess
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vr_770, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="proxyreq"
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="uri"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="unparsed_uri"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
}

predicate func_8(Parameter vr_770, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="scheme"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
}

predicate func_9(Parameter vr_770, BlockStmt target_9) {
		target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ap_matches_request_vhost")
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_770
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="hostname"
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parsed_uri"
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="port_str"
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="port"
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("ap_run_default_port")
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="proxyreq"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="uri"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="unparsed_uri"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_770
}

from Function func, Variable vconf_773, Parameter vr_770, LogicalAndExpr target_3, EqualityOperation target_5, LogicalAndExpr target_6, BlockStmt target_7, ValueFieldAccess target_8, BlockStmt target_9
where
not func_0(vr_770, target_7)
and not func_1(vr_770, target_8)
and func_3(vconf_773, vr_770, target_9, target_3)
and func_5(vr_770, target_7, target_5)
and func_6(func, target_6)
and func_7(vr_770, target_7)
and func_8(vr_770, target_8)
and func_9(vr_770, target_9)
and vconf_773.getType().hasName("proxy_server_conf *")
and vr_770.getType().hasName("request_rec *")
and vconf_773.(LocalVariable).getFunction() = func
and vr_770.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
