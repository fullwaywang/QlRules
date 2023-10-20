/**
 * @name curl-c43127414d-smtp_connect
 * @id cpp/curl/c43127414d/smtp-connect
 * @description curl-c43127414d-lib/smtp.c-smtp_connect CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresult_1301, LogicalAndExpr target_9, IfStmt target_0) {
		target_0.getCondition().(VariableAccess).getTarget()=vresult_1301
		and target_0.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1301
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_1(Parameter vdone_1299, Variable vresult_1301, Parameter vconn_1299, EqualityOperation target_10, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1301
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("smtp_multi_statemach")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1299
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdone_1299
		and target_1.getParent().(IfStmt).getCondition()=target_10
}

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vresult_1301, Variable vdata_1303, Parameter vconn_1299, Function func, IfStmt target_3) {
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="protocol"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1299
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="131072"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1303
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1301
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

/*predicate func_4(Variable vresult_1301, LogicalAndExpr target_9, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1301
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

*/
predicate func_5(Variable vresult_1301, ExprStmt target_11, Function func, IfStmt target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vresult_1301
		and target_5.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1301
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getCondition().(VariableAccess).getLocation())
}

predicate func_6(Parameter vdone_1299, Variable vresult_1301, Variable vdata_1303, Parameter vconn_1299, Function func, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1303
		and target_6.getThen() instanceof ExprStmt
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1301
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("smtp_easy_statemach")
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1299
		and target_6.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_1301
		and target_6.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1299
		and target_6.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

/*predicate func_7(Variable vresult_1301, Parameter vconn_1299, EqualityOperation target_10, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1301
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("smtp_easy_statemach")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1299
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

*/
/*predicate func_8(Parameter vdone_1299, Variable vresult_1301, EqualityOperation target_10, IfStmt target_8) {
		target_8.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_1301
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1299
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

*/
predicate func_9(LogicalAndExpr target_9) {
		target_9.getAnOperand() instanceof BitwiseAndExpr
		and target_9.getAnOperand() instanceof EqualityOperation
}

predicate func_10(EqualityOperation target_10) {
		target_10.getAnOperand() instanceof ValueFieldAccess
		and target_10.getAnOperand() instanceof EnumConstantAccess
}

predicate func_11(Variable vresult_1301, Parameter vconn_1299, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1301
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_urldecode")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1299
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="domain"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="1"
}

from Function func, Parameter vdone_1299, Variable vresult_1301, Variable vdata_1303, Parameter vconn_1299, IfStmt target_0, ExprStmt target_1, DeclStmt target_2, IfStmt target_3, IfStmt target_5, IfStmt target_6, LogicalAndExpr target_9, EqualityOperation target_10, ExprStmt target_11
where
func_0(vresult_1301, target_9, target_0)
and func_1(vdone_1299, vresult_1301, vconn_1299, target_10, target_1)
and func_2(func, target_2)
and func_3(vresult_1301, vdata_1303, vconn_1299, func, target_3)
and func_5(vresult_1301, target_11, func, target_5)
and func_6(vdone_1299, vresult_1301, vdata_1303, vconn_1299, func, target_6)
and func_9(target_9)
and func_10(target_10)
and func_11(vresult_1301, vconn_1299, target_11)
and vdone_1299.getType().hasName("bool *")
and vresult_1301.getType().hasName("CURLcode")
and vdata_1303.getType().hasName("SessionHandle *")
and vconn_1299.getType().hasName("connectdata *")
and vdone_1299.getParentScope+() = func
and vresult_1301.getParentScope+() = func
and vdata_1303.getParentScope+() = func
and vconn_1299.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
