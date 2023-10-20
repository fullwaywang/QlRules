/**
 * @name curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-ossl_connect_step1
 * @id cpp/curl/b09c8ee15771c614c4bf3ddac893cdb12187c844/ossl-connect-step1
 * @description curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-ossl_connect_step1 CVE-2021-22890
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_2479, Parameter vconn_2480) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("ossl_get_proxy_index")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="sessionid"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2479
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="sessionid"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ssl"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2479)
}

predicate func_2(Parameter vconn_2480, Variable vbackend_2512) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2512
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

predicate func_3(Parameter vdata_2479, Parameter vconn_2480, Parameter vsockindex_2480, Variable vssl_sessionid_3192) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2480
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_3.getThen().(Literal).getValue()="1"
		and target_3.getElse().(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_ssl_getsessionid")
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2479
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_2480
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vssl_sessionid_3192
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsockindex_2480)
}

predicate func_4(Parameter vdata_2479, Parameter vconn_2480, Variable vbackend_2512, Variable vdata_idx_3193, Variable vconnectdata_idx_3194, Variable vsockindex_idx_3195) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_idx_3193
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vconnectdata_idx_3194
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsockindex_idx_3195
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2512
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_idx_3193
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata_2479
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend_2512
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconnectdata_idx_3194
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vconn_2480)
}

predicate func_5(Parameter vconn_2480) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="sock"
		and target_5.getQualifier().(VariableAccess).getTarget()=vconn_2480)
}

predicate func_6(Parameter vdata_2479, Parameter vconn_2480, Parameter vsockindex_2480, Variable vssl_sessionid_3192) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("Curl_ssl_getsessionid")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vdata_2479
		and target_6.getArgument(1).(VariableAccess).getTarget()=vconn_2480
		and target_6.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vssl_sessionid_3192
		and target_6.getArgument(3).(Literal).getValue()="0"
		and target_6.getArgument(4).(VariableAccess).getTarget()=vsockindex_2480)
}

predicate func_7(Variable vbackend_2512) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="handle"
		and target_7.getQualifier().(VariableAccess).getTarget()=vbackend_2512)
}

from Function func, Parameter vdata_2479, Parameter vconn_2480, Parameter vsockindex_2480, Variable vbackend_2512, Variable vssl_sessionid_3192, Variable vdata_idx_3193, Variable vconnectdata_idx_3194, Variable vsockindex_idx_3195
where
not func_0(vdata_2479, vconn_2480)
and not func_2(vconn_2480, vbackend_2512)
and not func_3(vdata_2479, vconn_2480, vsockindex_2480, vssl_sessionid_3192)
and func_4(vdata_2479, vconn_2480, vbackend_2512, vdata_idx_3193, vconnectdata_idx_3194, vsockindex_idx_3195)
and vdata_2479.getType().hasName("Curl_easy *")
and vconn_2480.getType().hasName("connectdata *")
and func_5(vconn_2480)
and func_6(vdata_2479, vconn_2480, vsockindex_2480, vssl_sessionid_3192)
and vsockindex_2480.getType().hasName("int")
and vbackend_2512.getType().hasName("ssl_backend_data *")
and func_7(vbackend_2512)
and vssl_sessionid_3192.getType().hasName("void *")
and vdata_idx_3193.getType().hasName("int")
and vconnectdata_idx_3194.getType().hasName("int")
and vsockindex_idx_3195.getType().hasName("int")
and vdata_2479.getParentScope+() = func
and vconn_2480.getParentScope+() = func
and vsockindex_2480.getParentScope+() = func
and vbackend_2512.getParentScope+() = func
and vssl_sessionid_3192.getParentScope+() = func
and vdata_idx_3193.getParentScope+() = func
and vconnectdata_idx_3194.getParentScope+() = func
and vsockindex_idx_3195.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
