/**
 * @name curl-5ff2c5ff25750aba1a8f64fbcad8e5b891512584-ftp_statemach_act
 * @id cpp/curl/5ff2c5ff25750aba1a8f64fbcad8e5b891512584/ftp-statemach-act
 * @description curl-5ff2c5ff25750aba1a8f64fbcad8e5b891512584-lib/ftp.c-ftp_statemach_act CVE-2017-1000254
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_9, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(EqualityOperation target_10, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getType().hasName("bool")
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof DoStmt
		and target_1.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_1.getElse() instanceof BlockStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vstore_2781, EqualityOperation target_9, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstore_2781
		and target_2.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_3(Variable vresult_2601, Variable vdata_2603, Variable vftpc_2605, Variable vdir_2780, Variable vCurl_cfree, Parameter vconn_2599, EqualityOperation target_11, IfStmt target_3) {
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="server_os"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdir_2780
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_2601
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_pp_sendf")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pp"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SYST"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vresult_2601
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdir_2780
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_2601
		and target_3.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_3.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_3.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_3.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdir_2780
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2603
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Entry path is '%s'\n"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="most_recent_ftp_entrypath"
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2603
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_state")
		and target_3.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_2599
		and target_3.getThen().(BlockStmt).getStmt(7).(BreakStmt).toString() = "break;"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_4(Variable vftpc_2605, Variable vCurl_cfree, EqualityOperation target_11, DoStmt target_4) {
		target_4.getCondition().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_5(Variable vftpc_2605, Variable vdir_2780, EqualityOperation target_11, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdir_2780
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_6(Variable vdata_2603, Variable vftpc_2605, EqualityOperation target_11, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2603
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Entry path is '%s'\n"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_7(Variable vdata_2603, Variable vftpc_2605, EqualityOperation target_11, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="most_recent_ftp_entrypath"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2603
		and target_7.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="entrypath"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vftpc_2605
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_8(Variable vdata_2603, Variable vdir_2780, Variable vCurl_cfree, EqualityOperation target_11, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cfree
		and target_8.getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdir_2780
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2603
		and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to figure out path\n"
		and target_8.getParent().(IfStmt).getCondition()=target_11
}

predicate func_9(EqualityOperation target_9) {
		target_9.getAnOperand().(CharLiteral).getValue()="34"
		and target_9.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_10(EqualityOperation target_10) {
		target_10.getAnOperand().(Literal).getValue()="257"
}

predicate func_11(EqualityOperation target_11) {
		target_11.getAnOperand().(CharLiteral).getValue()="34"
}

from Function func, Variable vresult_2601, Variable vdata_2603, Variable vftpc_2605, Variable vdir_2780, Variable vstore_2781, Variable vCurl_cfree, Parameter vconn_2599, ExprStmt target_2, IfStmt target_3, DoStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, BlockStmt target_8, EqualityOperation target_9, EqualityOperation target_10, EqualityOperation target_11
where
not func_0(target_9, func)
and not func_1(target_10, func)
and func_2(vstore_2781, target_9, target_2)
and func_3(vresult_2601, vdata_2603, vftpc_2605, vdir_2780, vCurl_cfree, vconn_2599, target_11, target_3)
and func_4(vftpc_2605, vCurl_cfree, target_11, target_4)
and func_5(vftpc_2605, vdir_2780, target_11, target_5)
and func_6(vdata_2603, vftpc_2605, target_11, target_6)
and func_7(vdata_2603, vftpc_2605, target_11, target_7)
and func_8(vdata_2603, vdir_2780, vCurl_cfree, target_11, target_8)
and func_9(target_9)
and func_10(target_10)
and func_11(target_11)
and vresult_2601.getType().hasName("CURLcode")
and vdata_2603.getType().hasName("Curl_easy *")
and vftpc_2605.getType().hasName("ftp_conn *")
and vdir_2780.getType().hasName("char *")
and vstore_2781.getType().hasName("char *")
and vCurl_cfree.getType().hasName("curl_free_callback")
and vconn_2599.getType().hasName("connectdata *")
and vresult_2601.getParentScope+() = func
and vdata_2603.getParentScope+() = func
and vftpc_2605.getParentScope+() = func
and vdir_2780.getParentScope+() = func
and vstore_2781.getParentScope+() = func
and not vCurl_cfree.getParentScope+() = func
and vconn_2599.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
