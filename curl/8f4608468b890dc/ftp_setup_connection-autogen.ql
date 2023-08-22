/**
 * @name curl-8f4608468b890dc-ftp_setup_connection
 * @id cpp/curl/8f4608468b890dc/ftp-setup-connection
 * @description curl-8f4608468b890dc-lib/ftp.c-ftp_setup_connection CVE-2023-27535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_4358, Variable vftp_4362, ValueFieldAccess target_10, NotExpr target_11, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="account"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getType().hasName("curl_strdup_callback")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="account"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getType().hasName("curl_free_callback")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vftp_4362
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_4358, Variable vftp_4362, ExprStmt target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_1.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alternative_to_user"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getType().hasName("curl_strdup_callback")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="alternative_to_user"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getType().hasName("curl_free_callback")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vftp_4362
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1)
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdata_4358, Variable vftp_4362, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ftp"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vftp_4362
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_2))
}

predicate func_4(Function func) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="known_filesize"
		and target_4.getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vdata_4358, ExprStmt target_14, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="use_ssl"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_5)
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vdata_4358, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ccc"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ftp_ccc"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_6))
}

predicate func_7(Parameter vdata_4358, Variable vftp_4362, Variable vCurl_ccalloc, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vftp_4362
		and target_7.getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_7.getRValue().(VariableCall).getArgument(0).(SizeofTypeOperator).getType() instanceof LongType
		and target_7.getRValue().(VariableCall).getArgument(0).(SizeofTypeOperator).getValue()="32"
		and target_7.getRValue().(VariableCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ftp"
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_7.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
}

predicate func_8(Parameter vconn_4359, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="ftpc"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4359
}

predicate func_9(Function func, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="known_filesize"
		and target_9.getQualifier() instanceof ValueFieldAccess
		and target_9.getParent().(AssignExpr).getLValue() = target_9
		and target_9.getParent().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Parameter vdata_4358, ValueFieldAccess target_10) {
		target_10.getTarget().getName()="p"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
}

predicate func_11(Variable vftp_4362, NotExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vftp_4362
}

predicate func_12(Variable vftp_4362, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="path"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftp_4362
		and target_12.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="path"
		and target_12.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="up"
		and target_12.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_12.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_14(Parameter vdata_4358, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="prefer_ascii"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vdata_4358, Parameter vconn_4359, Variable vftp_4362, Variable vCurl_ccalloc, AssignExpr target_7, ValueFieldAccess target_8, ValueFieldAccess target_9, ValueFieldAccess target_10, NotExpr target_11, ExprStmt target_12, ExprStmt target_14
where
not func_0(vdata_4358, vftp_4362, target_10, target_11, func)
and not func_1(vdata_4358, vftp_4362, target_12, func)
and not func_2(vdata_4358, vftp_4362, func)
and not func_4(func)
and not func_5(vdata_4358, target_14, func)
and not func_6(vdata_4358, func)
and func_7(vdata_4358, vftp_4362, vCurl_ccalloc, target_7)
and func_8(vconn_4359, target_8)
and func_9(func, target_9)
and func_10(vdata_4358, target_10)
and func_11(vftp_4362, target_11)
and func_12(vftp_4362, target_12)
and func_14(vdata_4358, target_14)
and vdata_4358.getType().hasName("Curl_easy *")
and vconn_4359.getType().hasName("connectdata *")
and vftp_4362.getType().hasName("FTP *")
and vCurl_ccalloc.getType().hasName("curl_calloc_callback")
and vdata_4358.getFunction() = func
and vconn_4359.getFunction() = func
and vftp_4362.(LocalVariable).getFunction() = func
and not vCurl_ccalloc.getParentScope+() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
