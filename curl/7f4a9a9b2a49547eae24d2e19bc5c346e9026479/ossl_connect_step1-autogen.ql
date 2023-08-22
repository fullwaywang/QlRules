/**
 * @name curl-7f4a9a9b2a49547eae24d2e19bc5c346e9026479-ossl_connect_step1
 * @id cpp/curl/7f4a9a9b2a49547eae24d2e19bc5c346e9026479/ossl-connect-step1
 * @description curl-7f4a9a9b2a49547eae24d2e19bc5c346e9026479-lib/vtls/openssl.c-ossl_connect_step1 CVE-2021-22901
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsockindex_2575, Parameter vdata_2574, Parameter vconn_2575, AddressOfExpr target_21, NotExpr target_22, ExprStmt target_23, ArrayExpr target_24, PointerArithmeticOperation target_25) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ossl_associate_connection")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_0.getArgument(1).(VariableAccess).getTarget()=vconn_2575
		and target_0.getArgument(2).(VariableAccess).getTarget()=vsockindex_2575
		and target_21.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation())
		and target_0.getArgument(2).(VariableAccess).getLocation().isBefore(target_22.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_24.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vconn_2575, EqualityOperation target_1) {
		target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

/*predicate func_2(Parameter vconn_2575, EqualityOperation target_2) {
		target_2.getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
}

*/
predicate func_3(Parameter vconn_2575, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

predicate func_4(Parameter vdata_2574, ConditionalExpr target_26, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("Curl_ssl_sessionid_lock")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
}

predicate func_5(Parameter vsockindex_2575, Variable vbackend_2610, Variable vssl_sessionid_3230, Parameter vdata_2574, Parameter vconn_2575, ConditionalExpr target_26, IfStmt target_5) {
		target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_ssl_getsessionid")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_2575
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vssl_sessionid_3230
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsockindex_2575
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("SSL_set_session")
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vssl_sessionid_3230
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_ssl_sessionid_unlock")
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SSL: SSL_set_session failed: %s"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("ossl_strerror")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SSL re-using session ID\n"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
}

predicate func_6(Parameter vdata_2574, ConditionalExpr target_26, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("Curl_ssl_sessionid_unlock")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
}

predicate func_7(ConditionalExpr target_26, Function func, DeclStmt target_7) {
		target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Parameter vdata_2574, VariableAccess target_8) {
		target_8.getTarget()=vdata_2574
}

predicate func_9(Parameter vconn_2575, VariableAccess target_9) {
		target_9.getTarget()=vconn_2575
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Parameter vsockindex_2575, VariableAccess target_10) {
		target_10.getTarget()=vsockindex_2575
		and target_10.getParent().(PointerAddExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_11(Variable vdata_idx_3231, Variable vconnectdata_idx_3232, Variable vsockindex_idx_3233, Variable vproxy_idx_3234, Parameter vdata_2574, Parameter vconn_2575, Function func, IfStmt target_11) {
		target_11.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_11.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_11.getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="sessionid"
		and target_11.getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_11.getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_11.getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_11.getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2574
		and target_11.getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="sessionid"
		and target_11.getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_11.getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_11.getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_11.getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2574
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsockindex_idx_3233
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vproxy_idx_3234
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_idx_3231
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata_2574
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconnectdata_idx_3232
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vconn_2575
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsockindex_idx_3233
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_11.getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vproxy_idx_3234
		and target_11.getThen().(BlockStmt).getStmt(6) instanceof ExprStmt
		and target_11.getThen().(BlockStmt).getStmt(7) instanceof IfStmt
		and target_11.getThen().(BlockStmt).getStmt(8) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(ConditionalExpr target_26, Function func, DeclStmt target_12) {
		target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_12.getEnclosingFunction() = func
}

predicate func_13(ConditionalExpr target_26, Function func, DeclStmt target_13) {
		target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_13.getEnclosingFunction() = func
}

predicate func_14(ConditionalExpr target_26, Function func, DeclStmt target_14) {
		target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_14.getEnclosingFunction() = func
}

predicate func_15(ConditionalExpr target_26, Function func, DeclStmt target_15) {
		target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_15.getEnclosingFunction() = func
}

/*predicate func_16(Parameter vsockindex_2575, Variable vbackend_2610, Variable vdata_idx_3231, Variable vconnectdata_idx_3232, Variable vsockindex_idx_3233, Variable vproxy_idx_3234, Parameter vdata_2574, Parameter vconn_2575, ConditionalExpr target_26, IfStmt target_16) {
		target_16.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_idx_3231
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vconnectdata_idx_3232
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsockindex_idx_3233
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vproxy_idx_3234
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_idx_3231
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata_2574
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconnectdata_idx_3232
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vconn_2575
		and target_16.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_16.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_16.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_16.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsockindex_idx_3233
		and target_16.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sock"
		and target_16.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_16.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsockindex_2575
		and target_16.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_16.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_16.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_16.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vproxy_idx_3234
		and target_16.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition() instanceof LogicalAndExpr
		and target_16.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_16.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
}

*/
/*predicate func_17(Variable vbackend_2610, Variable vdata_idx_3231, Parameter vdata_2574, FunctionCall target_17) {
		target_17.getTarget().hasName("SSL_set_ex_data")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_17.getArgument(1).(VariableAccess).getTarget()=vdata_idx_3231
		and target_17.getArgument(2).(VariableAccess).getTarget()=vdata_2574
}

*/
/*predicate func_18(Variable vbackend_2610, Variable vconnectdata_idx_3232, Parameter vconn_2575, LogicalAndExpr target_27, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_18.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_18.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_18.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconnectdata_idx_3232
		and target_18.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vconn_2575
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
}

*/
/*predicate func_19(Parameter vsockindex_2575, Variable vbackend_2610, Variable vsockindex_idx_3233, Parameter vconn_2575, LogicalAndExpr target_27, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_19.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsockindex_idx_3233
		and target_19.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sock"
		and target_19.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_19.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsockindex_2575
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
}

*/
/*predicate func_20(Variable vbackend_2610, Variable vproxy_idx_3234, LogicalAndExpr target_27, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2610
		and target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vproxy_idx_3234
		and target_20.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition() instanceof LogicalAndExpr
		and target_20.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_20.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
}

*/
predicate func_21(Parameter vsockindex_2575, Parameter vconn_2575, AddressOfExpr target_21) {
		target_21.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_21.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_21.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsockindex_2575
}

predicate func_22(Parameter vsockindex_2575, Variable vssl_sessionid_3230, Parameter vdata_2574, Parameter vconn_2575, NotExpr target_22) {
		target_22.getOperand().(FunctionCall).getTarget().hasName("Curl_ssl_getsessionid")
		and target_22.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_22.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_2575
		and target_22.getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_22.getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_22.getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_22.getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_22.getOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_22.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vssl_sessionid_3230
		and target_22.getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_22.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsockindex_2575
}

predicate func_23(Parameter vdata_2574, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2574
		and target_23.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="WARNING: failed to configure server name indication (SNI) TLS extension\n"
}

predicate func_24(Parameter vconn_2575, ArrayExpr target_24) {
		target_24.getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_24.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_24.getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_24.getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_24.getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_24.getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_24.getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_24.getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

predicate func_25(Parameter vsockindex_2575, Parameter vconn_2575, PointerArithmeticOperation target_25) {
		target_25.getAnOperand().(PointerFieldAccess).getTarget().getName()="sock"
		and target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2575
		and target_25.getAnOperand().(VariableAccess).getTarget()=vsockindex_2575
}

predicate func_26(ConditionalExpr target_26) {
		target_26.getCondition() instanceof LogicalAndExpr
		and target_26.getThen() instanceof ValueFieldAccess
		and target_26.getElse() instanceof ValueFieldAccess
}

predicate func_27(LogicalAndExpr target_27) {
		target_27.getAnOperand() instanceof LogicalAndExpr
		and target_27.getAnOperand() instanceof RelationalOperation
}

from Function func, Parameter vsockindex_2575, Variable vbackend_2610, Variable vssl_sessionid_3230, Variable vdata_idx_3231, Variable vconnectdata_idx_3232, Variable vsockindex_idx_3233, Variable vproxy_idx_3234, Parameter vdata_2574, Parameter vconn_2575, EqualityOperation target_1, LogicalAndExpr target_3, ExprStmt target_4, IfStmt target_5, ExprStmt target_6, DeclStmt target_7, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, IfStmt target_11, DeclStmt target_12, DeclStmt target_13, DeclStmt target_14, DeclStmt target_15, AddressOfExpr target_21, NotExpr target_22, ExprStmt target_23, ArrayExpr target_24, PointerArithmeticOperation target_25, ConditionalExpr target_26, LogicalAndExpr target_27
where
not func_0(vsockindex_2575, vdata_2574, vconn_2575, target_21, target_22, target_23, target_24, target_25)
and func_1(vconn_2575, target_1)
and func_3(vconn_2575, target_3)
and func_4(vdata_2574, target_26, target_4)
and func_5(vsockindex_2575, vbackend_2610, vssl_sessionid_3230, vdata_2574, vconn_2575, target_26, target_5)
and func_6(vdata_2574, target_26, target_6)
and func_7(target_26, func, target_7)
and func_8(vdata_2574, target_8)
and func_9(vconn_2575, target_9)
and func_10(vsockindex_2575, target_10)
and func_11(vdata_idx_3231, vconnectdata_idx_3232, vsockindex_idx_3233, vproxy_idx_3234, vdata_2574, vconn_2575, func, target_11)
and func_12(target_26, func, target_12)
and func_13(target_26, func, target_13)
and func_14(target_26, func, target_14)
and func_15(target_26, func, target_15)
and func_21(vsockindex_2575, vconn_2575, target_21)
and func_22(vsockindex_2575, vssl_sessionid_3230, vdata_2574, vconn_2575, target_22)
and func_23(vdata_2574, target_23)
and func_24(vconn_2575, target_24)
and func_25(vsockindex_2575, vconn_2575, target_25)
and func_26(target_26)
and func_27(target_27)
and vsockindex_2575.getType().hasName("int")
and vbackend_2610.getType().hasName("ssl_backend_data *")
and vssl_sessionid_3230.getType().hasName("void *")
and vdata_idx_3231.getType().hasName("int")
and vconnectdata_idx_3232.getType().hasName("int")
and vsockindex_idx_3233.getType().hasName("int")
and vproxy_idx_3234.getType().hasName("int")
and vdata_2574.getType().hasName("Curl_easy *")
and vconn_2575.getType().hasName("connectdata *")
and vsockindex_2575.getFunction() = func
and vbackend_2610.(LocalVariable).getFunction() = func
and vssl_sessionid_3230.(LocalVariable).getFunction() = func
and vdata_idx_3231.(LocalVariable).getFunction() = func
and vconnectdata_idx_3232.(LocalVariable).getFunction() = func
and vsockindex_idx_3233.(LocalVariable).getFunction() = func
and vproxy_idx_3234.(LocalVariable).getFunction() = func
and vdata_2574.getFunction() = func
and vconn_2575.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
