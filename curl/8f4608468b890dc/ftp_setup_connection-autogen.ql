/**
 * @name curl-8f4608468b890dc-ftp_setup_connection
 * @id cpp/curl/8f4608468b890dc/ftp-setup-connection
 * @description curl-8f4608468b890dc-lib/ftp.c-ftp_setup_connection CVE-2023-27535
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_4358, Variable vftp_4362, ValueFieldAccess target_12, ExprStmt target_13, Function func) {
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
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vftp_4362, ExprStmt target_13) {
	exists(VariableCall target_1 |
		target_1.getExpr().(VariableAccess).getType().hasName("curl_free_callback")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vftp_4362
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_2(Parameter vdata_4358, Variable vftp_4362, NotExpr target_14, ExprStmt target_15, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_2.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_2.getCondition().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alternative_to_user"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getType().hasName("curl_strdup_callback")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="str"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="alternative_to_user"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getType().hasName("curl_free_callback")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vftp_4362
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_2)
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vdata_4358, Variable vftp_4362, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ftp"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vftp_4362
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3))
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="known_filesize"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_5))
}

/*predicate func_6(Function func) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="known_filesize"
		and target_6.getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_7(Parameter vdata_4358, ExprStmt target_16, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="use_ssl"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_7)
		and target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vdata_4358, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ccc"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ftp_conn *")
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ftp_ccc"
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_8))
}

predicate func_9(Parameter vdata_4358, Variable vftp_4362, Variable vCurl_ccalloc, AssignExpr target_9) {
		target_9.getLValue().(VariableAccess).getTarget()=vftp_4362
		and target_9.getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_9.getRValue().(VariableCall).getArgument(0).(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getRValue().(VariableCall).getArgument(0).(SizeofTypeOperator).getValue()="32"
		and target_9.getRValue().(VariableCall).getArgument(1).(Literal).getValue()="1"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ftp"
		and target_9.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_9.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_9.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
}

predicate func_10(Parameter vconn_4359, ValueFieldAccess target_10) {
		target_10.getTarget().getName()="ftpc"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="proto"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_4359
}

predicate func_11(Function func, ValueFieldAccess target_11) {
		target_11.getTarget().getName()="known_filesize"
		and target_11.getQualifier() instanceof ValueFieldAccess
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Parameter vdata_4358, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="p"
		and target_12.getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_12.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
}

predicate func_13(Variable vftp_4362, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="downloadsize"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftp_4362
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_14(Variable vftp_4362, NotExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vftp_4362
}

predicate func_15(Variable vftp_4362, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="path"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftp_4362
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="path"
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="up"
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_16(Parameter vdata_4358, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="prefer_ascii"
		and target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_4358
		and target_16.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vdata_4358, Parameter vconn_4359, Variable vftp_4362, Variable vCurl_ccalloc, AssignExpr target_9, ValueFieldAccess target_10, ValueFieldAccess target_11, ValueFieldAccess target_12, ExprStmt target_13, NotExpr target_14, ExprStmt target_15, ExprStmt target_16
where
not func_0(vdata_4358, vftp_4362, target_12, target_13, func)
and not func_2(vdata_4358, vftp_4362, target_14, target_15, func)
and not func_3(vdata_4358, vftp_4362, func)
and not func_5(func)
and not func_7(vdata_4358, target_16, func)
and not func_8(vdata_4358, func)
and func_9(vdata_4358, vftp_4362, vCurl_ccalloc, target_9)
and func_10(vconn_4359, target_10)
and func_11(func, target_11)
and func_12(vdata_4358, target_12)
and func_13(vftp_4362, target_13)
and func_14(vftp_4362, target_14)
and func_15(vftp_4362, target_15)
and func_16(vdata_4358, target_16)
and vdata_4358.getType().hasName("Curl_easy *")
and vconn_4359.getType().hasName("connectdata *")
and vftp_4362.getType().hasName("FTP *")
and vCurl_ccalloc.getType().hasName("curl_calloc_callback")
and vdata_4358.getParentScope+() = func
and vconn_4359.getParentScope+() = func
and vftp_4362.getParentScope+() = func
and not vCurl_ccalloc.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
