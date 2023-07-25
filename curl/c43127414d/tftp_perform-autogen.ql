/**
 * @name curl-c43127414d-tftp_perform
 * @id cpp/curl/c43127414d/tftp-perform
 * @description curl-c43127414d-lib/tftp.c-tftp_perform CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_1395, Parameter vdophase_done_1395, EqualityOperation target_4, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("tftp_multi_statemach")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1395
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdophase_done_1395
		and target_0.getParent().(IfStmt).getCondition()=target_4
}

predicate func_1(Parameter vconn_1395, Parameter vdophase_done_1395, Variable vresult_1397, Function func, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1395
		and target_1.getThen() instanceof ExprStmt
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1397
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tftp_easy_statemach")
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1395
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdophase_done_1395
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

/*predicate func_2(Parameter vconn_1395, Variable vresult_1397, EqualityOperation target_4, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1397
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tftp_easy_statemach")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1395
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

*/
/*predicate func_3(Parameter vdophase_done_1395, EqualityOperation target_4, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdophase_done_1395
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

*/
predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand() instanceof ValueFieldAccess
		and target_4.getAnOperand() instanceof EnumConstantAccess
}

from Function func, Parameter vconn_1395, Parameter vdophase_done_1395, Variable vresult_1397, ExprStmt target_0, IfStmt target_1, EqualityOperation target_4
where
func_0(vconn_1395, vdophase_done_1395, target_4, target_0)
and func_1(vconn_1395, vdophase_done_1395, vresult_1397, func, target_1)
and func_4(target_4)
and vconn_1395.getType().hasName("connectdata *")
and vdophase_done_1395.getType().hasName("bool *")
and vresult_1397.getType().hasName("CURLcode")
and vconn_1395.getParentScope+() = func
and vdophase_done_1395.getParentScope+() = func
and vresult_1397.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
