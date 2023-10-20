/**
 * @name curl-c43127414d-ftp_connect
 * @id cpp/curl/c43127414d/ftp-connect
 * @description curl-c43127414d-lib/ftp.c-ftp_connect CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_3204, FunctionCall target_0) {
		target_0.getTarget().hasName("state")
		and not target_0.getTarget().hasName("_state")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vconn_3204
}

predicate func_1(Parameter vconn_3204, Parameter vdone_3205, Variable vresult_3207, EqualityOperation target_6, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3207
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_multi_statemach")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_3204
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdone_3205
		and target_1.getParent().(IfStmt).getCondition()=target_6
}

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vconn_3204, Parameter vdone_3205, Variable vresult_3207, Variable vdata_3209, Function func, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3209
		and target_3.getThen() instanceof ExprStmt
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3207
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_easy_statemach")
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_3204
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_3207
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_3205
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

/*predicate func_4(Parameter vconn_3204, Variable vresult_3207, EqualityOperation target_6, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_3207
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_easy_statemach")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_3204
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
/*predicate func_5(Parameter vdone_3205, Variable vresult_3207, EqualityOperation target_6, IfStmt target_5) {
		target_5.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_3207
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_3205
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
predicate func_6(EqualityOperation target_6) {
		target_6.getAnOperand() instanceof ValueFieldAccess
		and target_6.getAnOperand() instanceof EnumConstantAccess
}

from Function func, Parameter vconn_3204, Parameter vdone_3205, Variable vresult_3207, Variable vdata_3209, FunctionCall target_0, ExprStmt target_1, DeclStmt target_2, IfStmt target_3, EqualityOperation target_6
where
func_0(vconn_3204, target_0)
and func_1(vconn_3204, vdone_3205, vresult_3207, target_6, target_1)
and func_2(func, target_2)
and func_3(vconn_3204, vdone_3205, vresult_3207, vdata_3209, func, target_3)
and func_6(target_6)
and vconn_3204.getType().hasName("connectdata *")
and vdone_3205.getType().hasName("bool *")
and vresult_3207.getType().hasName("CURLcode")
and vdata_3209.getType().hasName("SessionHandle *")
and vconn_3204.getParentScope+() = func
and vdone_3205.getParentScope+() = func
and vresult_3207.getParentScope+() = func
and vdata_3209.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
