/**
 * @name curl-c43127414d-pop3_connect
 * @id cpp/curl/c43127414d/pop3-connect
 * @description curl-c43127414d-lib/pop3.c-pop3_connect CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_1300, Parameter vdone_1300, Variable vresult_1302, EqualityOperation target_5, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1302
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_multi_statemach")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1300
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdone_1300
		and target_0.getParent().(IfStmt).getCondition()=target_5
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vconn_1300, Parameter vdone_1300, Variable vresult_1302, Variable vdata_1304, Function func, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1304
		and target_2.getThen() instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1302
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_easy_statemach")
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1300
		and target_2.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_1302
		and target_2.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1300
		and target_2.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(Parameter vconn_1300, Variable vresult_1302, EqualityOperation target_5, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1302
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_easy_statemach")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1300
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

*/
/*predicate func_4(Parameter vdone_1300, Variable vresult_1302, EqualityOperation target_5, IfStmt target_4) {
		target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_1302
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1300
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

*/
predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand() instanceof ValueFieldAccess
		and target_5.getAnOperand() instanceof EnumConstantAccess
}

from Function func, Parameter vconn_1300, Parameter vdone_1300, Variable vresult_1302, Variable vdata_1304, ExprStmt target_0, DeclStmt target_1, IfStmt target_2, EqualityOperation target_5
where
func_0(vconn_1300, vdone_1300, vresult_1302, target_5, target_0)
and func_1(func, target_1)
and func_2(vconn_1300, vdone_1300, vresult_1302, vdata_1304, func, target_2)
and func_5(target_5)
and vconn_1300.getType().hasName("connectdata *")
and vdone_1300.getType().hasName("bool *")
and vresult_1302.getType().hasName("CURLcode")
and vdata_1304.getType().hasName("SessionHandle *")
and vconn_1300.getParentScope+() = func
and vdone_1300.getParentScope+() = func
and vresult_1302.getParentScope+() = func
and vdata_1304.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
