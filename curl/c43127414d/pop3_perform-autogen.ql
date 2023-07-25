/**
 * @name curl-c43127414d-pop3_perform
 * @id cpp/curl/c43127414d/pop3-perform
 * @description curl-c43127414d-lib/pop3.c-pop3_perform CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdophase_done_1400, Variable vresult_1403, Parameter vconn_1399, EqualityOperation target_4, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1403
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_multi_statemach")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1399
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdophase_done_1400
		and target_0.getParent().(IfStmt).getCondition()=target_4
}

predicate func_1(Parameter vdophase_done_1400, Variable vresult_1403, Parameter vconn_1399, Function func, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1399
		and target_1.getThen() instanceof ExprStmt
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1403
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_easy_statemach")
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1399
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdophase_done_1400
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

/*predicate func_2(Variable vresult_1403, Parameter vconn_1399, EqualityOperation target_4, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1403
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_easy_statemach")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1399
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

*/
/*predicate func_3(Parameter vdophase_done_1400, EqualityOperation target_4, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdophase_done_1400
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

*/
predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand() instanceof ValueFieldAccess
		and target_4.getAnOperand() instanceof EnumConstantAccess
}

from Function func, Parameter vdophase_done_1400, Variable vresult_1403, Parameter vconn_1399, ExprStmt target_0, IfStmt target_1, EqualityOperation target_4
where
func_0(vdophase_done_1400, vresult_1403, vconn_1399, target_4, target_0)
and func_1(vdophase_done_1400, vresult_1403, vconn_1399, func, target_1)
and func_4(target_4)
and vdophase_done_1400.getType().hasName("bool *")
and vresult_1403.getType().hasName("CURLcode")
and vconn_1399.getType().hasName("connectdata *")
and vdophase_done_1400.getParentScope+() = func
and vresult_1403.getParentScope+() = func
and vconn_1399.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
