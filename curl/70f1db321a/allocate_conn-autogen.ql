/**
 * @name curl-70f1db321a-allocate_conn
 * @id cpp/curl/70f1db321a/allocate-conn
 * @description curl-70f1db321a-lib/url.c-allocate_conn CVE-2017-8818
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, DeclStmt target_0) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Variable vconn_4179, Function func, IfStmt target_1) {
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vconn_4179
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vconn_4179, Variable vCurl_handler_dummy, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="handler"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vCurl_handler_dummy
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vconn_4179, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vconn_4179, Function func, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vconn_4179, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tempsock"
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vconn_4179, Function func, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tempsock"
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Variable vconn_4179, Function func, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="connection_id"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_7.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vconn_4179, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="port"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_8.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Variable vconn_4179, Function func, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="remote_port"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_9.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Variable vconn_4179, Function func, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("Curl_conncontrol")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_4179
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Variable vconn_4179, Function func, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="created"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curlx_tvnow")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_13.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_13.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_13.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Variable vconn_4179, Function func, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="socks_proxy"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Variable vconn_4179, Function func, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="proxy"
		and target_15.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_15.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_15.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_15.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_15.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Variable vconn_4179, Function func, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="httpproxy"
		and target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxy"
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_16.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Variable vconn_4179, Function func, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="socksproxy"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_17.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxy"
		and target_17.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_17.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_17.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="httpproxy"
		and target_17.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_17.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_17.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Variable vconn_4179, Parameter vdata_4177, Function func, IfStmt target_18) {
		target_18.getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="proxy"
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="socksproxy"
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_18.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

/*predicate func_19(Variable vconn_4179, LogicalAndExpr target_53, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="proxy"
		and target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_19.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_19.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
}

*/
/*predicate func_20(Variable vconn_4179, LogicalAndExpr target_53, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="socksproxy"
		and target_20.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_20.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
}

*/
predicate func_21(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="proxy_user_passwd"
		and target_21.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_21.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_21.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_21.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_21.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and target_21.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_21.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="tunnel_proxy"
		and target_22.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_22.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="tunnel_thru_httpproxy"
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
}

predicate func_23(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="user_passwd"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_23.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_23.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_23.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_23.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and target_23.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_23.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_23
}

predicate func_24(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ftp_use_epsv"
		and target_24.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_24.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_24.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ftp_use_epsv"
		and target_24.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_24.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_24
}

predicate func_25(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ftp_use_eprt"
		and target_25.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_25.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_25.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ftp_use_eprt"
		and target_25.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_25.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_25
}

predicate func_26(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="verifystatus"
		and target_26.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_26.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="verifystatus"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_26
}

predicate func_27(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="verifypeer"
		and target_27.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_27.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="verifypeer"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_28(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="verifyhost"
		and target_28.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_28.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="verifyhost"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28
}

predicate func_29(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="verifystatus"
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proxy_ssl_config"
		and target_29.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_29.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="verifystatus"
		and target_29.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_29.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_29.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_29.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29
}

predicate func_30(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="verifypeer"
		and target_30.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proxy_ssl_config"
		and target_30.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_30.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="verifypeer"
		and target_30.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_30.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_30.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_30.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_30
}

predicate func_31(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="verifyhost"
		and target_31.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proxy_ssl_config"
		and target_31.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="verifyhost"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_31
}

predicate func_32(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ip_version"
		and target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ipver"
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_32
}

predicate func_33(Variable vconn_4179, Variable vCurl_ccalloc, Parameter vdata_4177, Function func, IfStmt target_33) {
		target_33.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_pipeline_wanted")
		and target_33.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="multi"
		and target_33.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and target_33.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_33.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="master_buffer"
		and target_33.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="master_buffer"
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(Literal).getValue()="16384"
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
		and target_33.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="master_buffer"
		and target_33.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_33.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_33.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).getName() ="error"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_33
}

/*predicate func_34(Variable vconn_4179, Variable vCurl_ccalloc, LogicalAndExpr target_54, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="master_buffer"
		and target_34.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_34.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_34.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(Literal).getValue()="16384"
		and target_34.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_34.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_54
}

*/
/*predicate func_35(Variable vconn_4179, LogicalAndExpr target_54, IfStmt target_35) {
		target_35.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="master_buffer"
		and target_35.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_35.getThen().(GotoStmt).toString() = "goto ..."
		and target_35.getThen().(GotoStmt).getName() ="error"
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_54
}

*/
predicate func_36(Variable vconn_4179, Function func, ExprStmt target_36) {
		target_36.getExpr().(FunctionCall).getTarget().hasName("Curl_llist_init")
		and target_36.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="send_pipe"
		and target_36.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_36
}

predicate func_37(Variable vconn_4179, Function func, ExprStmt target_37) {
		target_37.getExpr().(FunctionCall).getTarget().hasName("Curl_llist_init")
		and target_37.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="recv_pipe"
		and target_37.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_37
}

predicate func_38(Variable vconn_4179, Variable vCurl_cstrdup, Parameter vdata_4177, Function func, IfStmt target_38) {
		target_38.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_38.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_38.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and target_38.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_38.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_38.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_38.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_38.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_38.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_38.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_38.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).getName() ="error"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_38
}

/*predicate func_39(Variable vconn_4179, Variable vCurl_cstrdup, Parameter vdata_4177, ArrayExpr target_55, ExprStmt target_39) {
		target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_39.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_39.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_39.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_39.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and target_39.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_55
}

*/
/*predicate func_40(Variable vconn_4179, ArrayExpr target_55, IfStmt target_40) {
		target_40.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_40.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_40.getThen().(GotoStmt).toString() = "goto ..."
		and target_40.getThen().(GotoStmt).getName() ="error"
		and target_40.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_55
}

*/
predicate func_41(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_41) {
		target_41.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="localportrange"
		and target_41.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_41.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="localportrange"
		and target_41.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_41.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_41
}

predicate func_42(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="localport"
		and target_42.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_42.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="localport"
		and target_42.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_42.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_42
}

predicate func_43(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fclosesocket"
		and target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_43.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="fclosesocket"
		and target_43.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_43.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_43
}

predicate func_44(Variable vconn_4179, Parameter vdata_4177, Function func, ExprStmt target_44) {
		target_44.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="closesocket_client"
		and target_44.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_44.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="closesocket_client"
		and target_44.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_44.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4177
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_44
}

predicate func_45(Variable vconn_4179, Function func, ReturnStmt target_45) {
		target_45.getExpr().(VariableAccess).getTarget()=vconn_4179
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_45
}

predicate func_46(Function func, LabelStmt target_46) {
		target_46.toString() = "label ...:"
		and target_46.getName() ="error"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_46
}

predicate func_47(Variable vconn_4179, Function func, ExprStmt target_47) {
		target_47.getExpr().(FunctionCall).getTarget().hasName("Curl_llist_destroy")
		and target_47.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="send_pipe"
		and target_47.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_47.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_47
}

predicate func_48(Variable vconn_4179, Function func, ExprStmt target_48) {
		target_48.getExpr().(FunctionCall).getTarget().hasName("Curl_llist_destroy")
		and target_48.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="recv_pipe"
		and target_48.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and target_48.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_48
}

predicate func_49(Variable vconn_4179, Variable vCurl_cfree, Function func, ExprStmt target_49) {
		target_49.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_49.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="master_buffer"
		and target_49.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_49
}

predicate func_50(Variable vconn_4179, Variable vCurl_cfree, Function func, ExprStmt target_50) {
		target_50.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_50.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="localdev"
		and target_50.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4179
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_50
}

predicate func_51(Variable vconn_4179, Variable vCurl_cfree, Function func, ExprStmt target_51) {
		target_51.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_51.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vconn_4179
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_51
}

predicate func_52(Function func, ReturnStmt target_52) {
		target_52.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_52
}

predicate func_53(LogicalAndExpr target_53) {
		target_53.getAnOperand() instanceof ArrayExpr
		and target_53.getAnOperand() instanceof PointerDereferenceExpr
}

predicate func_54(LogicalAndExpr target_54) {
		target_54.getAnOperand() instanceof FunctionCall
		and target_54.getAnOperand() instanceof NotExpr
}

predicate func_55(ArrayExpr target_55) {
		target_55.getArrayBase() instanceof ValueFieldAccess
		and target_55.getArrayOffset() instanceof EnumConstantAccess
}

from Function func, Variable vconn_4179, Variable vCurl_ccalloc, Variable vCurl_handler_dummy, Variable vCurl_cstrdup, Variable vCurl_cfree, Parameter vdata_4177, DeclStmt target_0, IfStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, IfStmt target_18, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_31, ExprStmt target_32, IfStmt target_33, ExprStmt target_36, ExprStmt target_37, IfStmt target_38, ExprStmt target_41, ExprStmt target_42, ExprStmt target_43, ExprStmt target_44, ReturnStmt target_45, LabelStmt target_46, ExprStmt target_47, ExprStmt target_48, ExprStmt target_49, ExprStmt target_50, ExprStmt target_51, ReturnStmt target_52, LogicalAndExpr target_53, LogicalAndExpr target_54, ArrayExpr target_55
where
func_0(func, target_0)
and func_1(vconn_4179, func, target_1)
and func_2(vconn_4179, vCurl_handler_dummy, func, target_2)
and func_3(vconn_4179, func, target_3)
and func_4(vconn_4179, func, target_4)
and func_5(vconn_4179, func, target_5)
and func_6(vconn_4179, func, target_6)
and func_7(vconn_4179, func, target_7)
and func_8(vconn_4179, func, target_8)
and func_9(vconn_4179, func, target_9)
and func_10(vconn_4179, func, target_10)
and func_11(vconn_4179, func, target_11)
and func_12(vconn_4179, vdata_4177, func, target_12)
and func_13(vconn_4179, vdata_4177, func, target_13)
and func_14(vconn_4179, func, target_14)
and func_15(vconn_4179, func, target_15)
and func_16(vconn_4179, func, target_16)
and func_17(vconn_4179, func, target_17)
and func_18(vconn_4179, vdata_4177, func, target_18)
and func_21(vconn_4179, vdata_4177, func, target_21)
and func_22(vconn_4179, vdata_4177, func, target_22)
and func_23(vconn_4179, vdata_4177, func, target_23)
and func_24(vconn_4179, vdata_4177, func, target_24)
and func_25(vconn_4179, vdata_4177, func, target_25)
and func_26(vconn_4179, vdata_4177, func, target_26)
and func_27(vconn_4179, vdata_4177, func, target_27)
and func_28(vconn_4179, vdata_4177, func, target_28)
and func_29(vconn_4179, vdata_4177, func, target_29)
and func_30(vconn_4179, vdata_4177, func, target_30)
and func_31(vconn_4179, vdata_4177, func, target_31)
and func_32(vconn_4179, vdata_4177, func, target_32)
and func_33(vconn_4179, vCurl_ccalloc, vdata_4177, func, target_33)
and func_36(vconn_4179, func, target_36)
and func_37(vconn_4179, func, target_37)
and func_38(vconn_4179, vCurl_cstrdup, vdata_4177, func, target_38)
and func_41(vconn_4179, vdata_4177, func, target_41)
and func_42(vconn_4179, vdata_4177, func, target_42)
and func_43(vconn_4179, vdata_4177, func, target_43)
and func_44(vconn_4179, vdata_4177, func, target_44)
and func_45(vconn_4179, func, target_45)
and func_46(func, target_46)
and func_47(vconn_4179, func, target_47)
and func_48(vconn_4179, func, target_48)
and func_49(vconn_4179, vCurl_cfree, func, target_49)
and func_50(vconn_4179, vCurl_cfree, func, target_50)
and func_51(vconn_4179, vCurl_cfree, func, target_51)
and func_52(func, target_52)
and func_53(target_53)
and func_54(target_54)
and func_55(target_55)
and vconn_4179.getType().hasName("connectdata *")
and vCurl_ccalloc.getType().hasName("curl_calloc_callback")
and vCurl_handler_dummy.getType().hasName("const Curl_handler")
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vdata_4177.getType().hasName("Curl_easy *")
and vconn_4179.getParentScope+() = func
and not vCurl_ccalloc.getParentScope+() = func
and not vCurl_handler_dummy.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
and not vCurl_cfree.getParentScope+() = func
and vdata_4177.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
