/**
 * @name curl-c43127414d-Curl_http_connect
 * @id cpp/curl/c43127414d/Curl-http-connect
 * @description curl-c43127414d-lib/http.c-Curl_http_connect CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresult_1299, Parameter vconn_1296, EqualityOperation target_6, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1299
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_proxy_connect")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1296
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_1(Variable vresult_1299, EqualityOperation target_6, IfStmt target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vresult_1299
		and target_1.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1299
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_2(Parameter vconn_1296, BlockStmt target_12, BitwiseAndExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="given"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1296
		and target_2.getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_2.getParent().(IfStmt).getThen()=target_12
}

predicate func_3(Parameter vdone_1296, EqualityOperation target_13, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1296
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_4(Function func, DeclStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vdata_1298, Parameter vconn_1296, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_1298
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1296
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vdata_1298, BlockStmt target_14, ExprStmt target_5, EqualityOperation target_13, EqualityOperation target_6) {
		target_6.getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1298
		and target_6.getParent().(IfStmt).getThen()=target_14
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_7(Parameter vdone_1296, Variable vdata_1298, Variable vresult_1299, Function func, IfStmt target_7) {
		target_7.getCondition() instanceof BitwiseAndExpr
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1298
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1299
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vresult_1299
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1299
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1299
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vresult_1299
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1299
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_7.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1296
		and target_7.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

/*predicate func_8(Variable vdata_1298, Variable vresult_1299, BitwiseAndExpr target_2, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1298
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1299
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vresult_1299
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1299
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1299
		and target_8.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vresult_1299
		and target_8.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1299
		and target_8.getElse().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

*/
predicate func_9(Variable vresult_1299, EqualityOperation target_13, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1299
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

/*predicate func_10(Variable vresult_1299, EqualityOperation target_13, ExprStmt target_9, IfStmt target_10) {
		target_10.getCondition().(VariableAccess).getTarget()=vresult_1299
		and target_10.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vresult_1299
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getCondition().(VariableAccess).getLocation())
}

*/
/*predicate func_11(Parameter vdone_1296, BitwiseAndExpr target_2, ExprStmt target_3, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdone_1296
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

*/
predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0) instanceof IfStmt
}

predicate func_13(EqualityOperation target_13) {
		target_13.getAnOperand() instanceof ValueFieldAccess
		and target_13.getAnOperand() instanceof EnumConstantAccess
}

predicate func_14(BlockStmt target_14) {
		target_14.getStmt(0) instanceof ExprStmt
		and target_14.getStmt(1) instanceof IfStmt
}

from Function func, Parameter vdone_1296, Variable vdata_1298, Variable vresult_1299, Parameter vconn_1296, ExprStmt target_0, IfStmt target_1, BitwiseAndExpr target_2, ExprStmt target_3, DeclStmt target_4, ExprStmt target_5, EqualityOperation target_6, IfStmt target_7, ExprStmt target_9, BlockStmt target_12, EqualityOperation target_13, BlockStmt target_14
where
func_0(vresult_1299, vconn_1296, target_6, target_0)
and func_1(vresult_1299, target_6, target_1)
and func_2(vconn_1296, target_12, target_2)
and func_3(vdone_1296, target_13, target_3)
and func_4(func, target_4)
and func_5(vdata_1298, vconn_1296, func, target_5)
and func_6(vdata_1298, target_14, target_5, target_13, target_6)
and func_7(vdone_1296, vdata_1298, vresult_1299, func, target_7)
and func_9(vresult_1299, target_13, target_9)
and func_12(target_12)
and func_13(target_13)
and func_14(target_14)
and vdone_1296.getType().hasName("bool *")
and vdata_1298.getType().hasName("SessionHandle *")
and vresult_1299.getType().hasName("CURLcode")
and vconn_1296.getType().hasName("connectdata *")
and vdone_1296.getParentScope+() = func
and vdata_1298.getParentScope+() = func
and vresult_1299.getParentScope+() = func
and vconn_1296.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
