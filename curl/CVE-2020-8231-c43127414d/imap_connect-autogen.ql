/**
 * @name curl-c43127414d-imap_connect
 * @id cpp/curl/c43127414d/imap-connect
 * @description curl-c43127414d-lib/imap.c-imap_connect CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_1356, Parameter vdone_1357, Variable vresult_1359, EqualityOperation target_8, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1359
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_multi_statemach")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1356
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdone_1357
		and target_0.getParent().(IfStmt).getCondition()=target_8
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vconn_1356, Variable vresult_1359, Variable vdata_1361, Function func, IfStmt target_2) {
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1356
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1361
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1359
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vresult_1359
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1359
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(Variable vresult_1359, LogicalAndExpr target_9, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1359
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

*/
/*predicate func_4(Variable vresult_1359, LogicalAndExpr target_9, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=vresult_1359
		and target_4.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1359
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

*/
predicate func_5(Parameter vconn_1356, Parameter vdone_1357, Variable vresult_1359, Variable vdata_1361, Function func, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1361
		and target_5.getThen() instanceof ExprStmt
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1359
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_easy_statemach")
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1356
		and target_5.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_1359
		and target_5.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1357
		and target_5.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

/*predicate func_6(Parameter vconn_1356, Variable vresult_1359, EqualityOperation target_8, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1359
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_easy_statemach")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1356
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
/*predicate func_7(Parameter vdone_1357, Variable vresult_1359, EqualityOperation target_8, IfStmt target_7) {
		target_7.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_1359
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1357
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
predicate func_8(EqualityOperation target_8) {
		target_8.getAnOperand() instanceof ValueFieldAccess
		and target_8.getAnOperand() instanceof EnumConstantAccess
}

predicate func_9(LogicalAndExpr target_9) {
		target_9.getAnOperand() instanceof BitwiseAndExpr
		and target_9.getAnOperand() instanceof EqualityOperation
}

from Function func, Parameter vconn_1356, Parameter vdone_1357, Variable vresult_1359, Variable vdata_1361, ExprStmt target_0, DeclStmt target_1, IfStmt target_2, IfStmt target_5, EqualityOperation target_8, LogicalAndExpr target_9
where
func_0(vconn_1356, vdone_1357, vresult_1359, target_8, target_0)
and func_1(func, target_1)
and func_2(vconn_1356, vresult_1359, vdata_1361, func, target_2)
and func_5(vconn_1356, vdone_1357, vresult_1359, vdata_1361, func, target_5)
and func_8(target_8)
and func_9(target_9)
and vconn_1356.getType().hasName("connectdata *")
and vdone_1357.getType().hasName("bool *")
and vresult_1359.getType().hasName("CURLcode")
and vdata_1361.getType().hasName("SessionHandle *")
and vconn_1356.getParentScope+() = func
and vdone_1357.getParentScope+() = func
and vresult_1359.getParentScope+() = func
and vdata_1361.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
