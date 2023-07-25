/**
 * @name curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-Curl_ssl_addsessionid
 * @id cpp/curl/b09c8ee15771c614c4bf3ddac893cdb12187c844/Curl-ssl-addsessionid
 * @description curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-Curl_ssl_addsessionid CVE-2021-22890
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Size_t
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vdata_481, Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="session"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vdata_481, Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="age"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="session"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Function func) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Parameter vsockindex_485, Parameter vconn_482, Function func) {
	exists(DeclStmt target_7 |
		target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="proxy_ssl_connected"
		and target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_7.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsockindex_485
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Variable visProxy_495, Parameter vconn_482, Function func) {
	exists(DeclStmt target_8 |
		target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=visProxy_495
		and target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="proxy_ssl_config"
		and target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Variable visProxy_495, Parameter vconn_482, Function func) {
	exists(DeclStmt target_9 |
		target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=visProxy_495
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="name"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="host"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="name"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="host"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Function func) {
	exists(DoStmt target_10 |
		target_10.getCondition().(Literal).getValue()="0"
		and target_10.getStmt().(BlockStmt).toString() = "{ ... }"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Variable vCurl_cstrdup, Variable vclone_host_490, Variable vhostname_499, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclone_host_490
		and target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vhostname_499
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_12(Variable vclone_host_490, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vclone_host_490
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

predicate func_13(Variable vCurl_cstrdup, Variable vCurl_cfree, Variable vclone_host_490, Variable vclone_conn_to_host_491, Parameter vconn_482, Function func) {
	exists(IfStmt target_13 |
		target_13.getCondition().(ValueFieldAccess).getTarget().getName()="conn_to_host"
		and target_13.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_13.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclone_conn_to_host_491
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="conn_to_host"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vclone_conn_to_host_491
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vclone_host_490
		and target_13.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclone_conn_to_host_491
		and target_13.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

predicate func_18(Variable vconn_to_port_492, Parameter vconn_482, Function func) {
	exists(IfStmt target_18 |
		target_18.getCondition().(ValueFieldAccess).getTarget().getName()="conn_to_port"
		and target_18.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_18.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vconn_to_port_492
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="conn_to_port"
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_18.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vconn_to_port_492
		and target_18.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_18.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18)
}

predicate func_19(Variable vgeneral_age_493, Parameter vdata_481, Function func) {
	exists(IfStmt target_19 |
		target_19.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="share"
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="specifier"
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="16"
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vgeneral_age_493
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sessionage"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="share"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vgeneral_age_493
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="sessionage"
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19)
}

predicate func_22(Variable vi_487, Variable vstore_488, Variable voldest_age_489, Parameter vdata_481, Function func) {
	exists(ForStmt target_22 |
		target_22.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_487
		and target_22.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_487
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="max_ssl_sessions"
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="general_ssl"
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="sessionid"
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="session"
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_487
		and target_22.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_487
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="age"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="session"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_487
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voldest_age_489
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voldest_age_489
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="age"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="session"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_487
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstore_488
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="session"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_22.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_487
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22)
}

predicate func_26(Variable vi_487, Variable vstore_488, Parameter vdata_481, Function func) {
	exists(IfStmt target_26 |
		target_26.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_487
		and target_26.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="max_ssl_sessions"
		and target_26.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="general_ssl"
		and target_26.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_26.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_26.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_ssl_kill_session")
		and target_26.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstore_488
		and target_26.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstore_488
		and target_26.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="session"
		and target_26.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_26.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_481
		and target_26.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_487
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_26)
}

predicate func_27(Parameter vssl_sessionid_483, Variable vstore_488, Function func) {
	exists(ExprStmt target_27 |
		target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sessionid"
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_27.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vssl_sessionid_483
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27)
}

predicate func_28(Parameter vidsize_484, Variable vstore_488, Function func) {
	exists(ExprStmt target_28 |
		target_28.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="idsize"
		and target_28.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_28.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vidsize_484
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28)
}

predicate func_29(Variable vstore_488, Variable vgeneral_age_493, Function func) {
	exists(ExprStmt target_29 |
		target_29.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="age"
		and target_29.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_29.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vgeneral_age_493
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29)
}

predicate func_30(Variable vCurl_cfree, Variable vstore_488, Function func) {
	exists(ExprStmt target_30 |
		target_30.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_30.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_30.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_30)
}

predicate func_31(Variable vCurl_cfree, Variable vstore_488, Function func) {
	exists(ExprStmt target_31 |
		target_31.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_31.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="conn_to_host"
		and target_31.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_31)
}

predicate func_32(Variable vstore_488, Variable vclone_host_490, Function func) {
	exists(ExprStmt target_32 |
		target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_32.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vclone_host_490
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_32)
}

predicate func_33(Variable vstore_488, Variable vclone_conn_to_host_491, Function func) {
	exists(ExprStmt target_33 |
		target_33.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="conn_to_host"
		and target_33.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_33.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vclone_conn_to_host_491
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_33)
}

predicate func_34(Variable vstore_488, Variable vconn_to_port_492, Function func) {
	exists(ExprStmt target_34 |
		target_34.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="conn_to_port"
		and target_34.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vconn_to_port_492
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_34)
}

predicate func_35(Variable vstore_488, Variable visProxy_495, Parameter vconn_482, Function func) {
	exists(ExprStmt target_35 |
		target_35.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="remote_port"
		and target_35.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_35.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=visProxy_495
		and target_35.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="port"
		and target_35.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and target_35.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="remote_port"
		and target_35.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_35)
}

predicate func_36(Variable vstore_488, Parameter vconn_482, Function func) {
	exists(ExprStmt target_36 |
		target_36.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="scheme"
		and target_36.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_36.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="scheme"
		and target_36.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_36.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_482
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_36)
}

predicate func_37(Variable vCurl_cfree, Variable vstore_488, Variable vclone_host_490, Variable vclone_conn_to_host_491, Variable vssl_config_496, Function func) {
	exists(IfStmt target_37 |
		target_37.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_clone_primary_ssl_config")
		and target_37.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vssl_config_496
		and target_37.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_37.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_free_primary_ssl_config")
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ssl_config"
		and target_37.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_37.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sessionid"
		and target_37.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstore_488
		and target_37.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_37.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_37.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vclone_host_490
		and target_37.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_37.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vclone_conn_to_host_491
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_37)
}

predicate func_43(Function func) {
	exists(ReturnStmt target_43 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_43)
}

from Function func, Variable vCurl_cstrdup, Variable vCurl_cfree, Parameter vssl_sessionid_483, Parameter vidsize_484, Parameter vsockindex_485, Variable vi_487, Variable vstore_488, Variable voldest_age_489, Variable vclone_host_490, Variable vclone_conn_to_host_491, Variable vconn_to_port_492, Variable vgeneral_age_493, Variable visProxy_495, Variable vssl_config_496, Variable vhostname_499, Parameter vdata_481, Parameter vconn_482
where
func_0(func)
and func_1(vdata_481, func)
and func_2(vdata_481, func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(vsockindex_485, vconn_482, func)
and func_8(visProxy_495, vconn_482, func)
and func_9(visProxy_495, vconn_482, func)
and func_10(func)
and func_11(vCurl_cstrdup, vclone_host_490, vhostname_499, func)
and func_12(vclone_host_490, func)
and func_13(vCurl_cstrdup, vCurl_cfree, vclone_host_490, vclone_conn_to_host_491, vconn_482, func)
and func_18(vconn_to_port_492, vconn_482, func)
and func_19(vgeneral_age_493, vdata_481, func)
and func_22(vi_487, vstore_488, voldest_age_489, vdata_481, func)
and func_26(vi_487, vstore_488, vdata_481, func)
and func_27(vssl_sessionid_483, vstore_488, func)
and func_28(vidsize_484, vstore_488, func)
and func_29(vstore_488, vgeneral_age_493, func)
and func_30(vCurl_cfree, vstore_488, func)
and func_31(vCurl_cfree, vstore_488, func)
and func_32(vstore_488, vclone_host_490, func)
and func_33(vstore_488, vclone_conn_to_host_491, func)
and func_34(vstore_488, vconn_to_port_492, func)
and func_35(vstore_488, visProxy_495, vconn_482, func)
and func_36(vstore_488, vconn_482, func)
and func_37(vCurl_cfree, vstore_488, vclone_host_490, vclone_conn_to_host_491, vssl_config_496, func)
and func_43(func)
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vssl_sessionid_483.getType().hasName("void *")
and vidsize_484.getType().hasName("size_t")
and vsockindex_485.getType().hasName("int")
and vi_487.getType().hasName("size_t")
and vstore_488.getType().hasName("Curl_ssl_session *")
and voldest_age_489.getType().hasName("long")
and vclone_host_490.getType().hasName("char *")
and vclone_conn_to_host_491.getType().hasName("char *")
and vconn_to_port_492.getType().hasName("int")
and vgeneral_age_493.getType().hasName("long *")
and visProxy_495.getType().hasName("const bool")
and vssl_config_496.getType().hasName("ssl_primary_config *const")
and vhostname_499.getType().hasName("const char *")
and vdata_481.getType().hasName("Curl_easy *")
and vconn_482.getType().hasName("connectdata *")
and not vCurl_cstrdup.getParentScope+() = func
and not vCurl_cfree.getParentScope+() = func
and vssl_sessionid_483.getParentScope+() = func
and vidsize_484.getParentScope+() = func
and vsockindex_485.getParentScope+() = func
and vi_487.getParentScope+() = func
and vstore_488.getParentScope+() = func
and voldest_age_489.getParentScope+() = func
and vclone_host_490.getParentScope+() = func
and vclone_conn_to_host_491.getParentScope+() = func
and vconn_to_port_492.getParentScope+() = func
and vgeneral_age_493.getParentScope+() = func
and visProxy_495.getParentScope+() = func
and vssl_config_496.getParentScope+() = func
and vhostname_499.getParentScope+() = func
and vdata_481.getParentScope+() = func
and vconn_482.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
