/**
 * @name curl-c43127414d-AllowServerConnect
 * @id cpp/curl/c43127414d/AllowServerConnect
 * @description curl-c43127414d-lib/ftp.c-AllowServerConnect CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_540, Variable vtimeout_ms_541, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtimeout_ms_541
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_timeleft_accept")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_540
}

predicate func_1(Variable vdata_540, Variable vtimeout_ms_541, IfStmt target_1) {
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtimeout_ms_541
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_540
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Accept timeout occurred while waiting server connect"
}

predicate func_2(Parameter vconn_538, Parameter vconnected_538, Variable vret_543, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_543
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReceivedServerConnect")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_538
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconnected_538
}

predicate func_3(Variable vret_543, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vret_543
		and target_3.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_543
}

predicate func_4(Parameter vconnected_538, Variable vdata_540, Variable vret_543, EqualityOperation target_14, IfStmt target_4) {
		target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_543
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vconnected_538
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="accepttimeout"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_540
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_expire")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_540
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="accepttimeout"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_expire")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_540
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="60000"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_5(Function func, DeclStmt target_5) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vconnected_538, Variable vret_543, ForStmt target_6) {
		target_6.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_6.getStmt().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vconnected_538
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_543
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcceptServerConnect")
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vret_543
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_543
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_543
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("InitiateTransfer")
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(VariableAccess).getTarget()=vret_543
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_543
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(4).(BreakStmt).toString() = "break;"
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_6.getStmt().(BlockStmt).getStmt(4).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
}

/*predicate func_7(PointerDereferenceExpr target_15, Function func, BreakStmt target_7) {
		target_7.toString() = "break;"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_7.getEnclosingFunction() = func
}

*/
/*predicate func_8(Variable vdata_540, Variable vtimeout_ms_541, Variable vinterval_ms_542, PointerDereferenceExpr target_15, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_540
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vinterval_ms_542
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1000"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtimeout_ms_541
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vinterval_ms_542
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vinterval_ms_542
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtimeout_ms_541
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_socket_check")
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vinterval_ms_542
		and target_8.getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_8.getElse().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

*/
/*predicate func_9(Variable vinterval_ms_542, EqualityOperation target_14, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vinterval_ms_542
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1000"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

*/
/*predicate func_10(Variable vtimeout_ms_541, Variable vinterval_ms_542, EqualityOperation target_14, IfStmt target_10) {
		target_10.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtimeout_ms_541
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vinterval_ms_542
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vinterval_ms_542
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtimeout_ms_541
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

*/
/*predicate func_11(Variable vinterval_ms_542, EqualityOperation target_14, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("Curl_socket_check")
		and target_11.getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_11.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_11.getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_11.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vinterval_ms_542
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

*/
/*predicate func_12(EqualityOperation target_14, Function func, BreakStmt target_12) {
		target_12.toString() = "break;"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_12.getEnclosingFunction() = func
}

*/
predicate func_13(Function func, LabelStmt target_13) {
		target_13.toString() = "label ...:"
		and target_13.getEnclosingFunction() = func
}

predicate func_14(EqualityOperation target_14) {
		target_14.getAnOperand() instanceof ValueFieldAccess
		and target_14.getAnOperand() instanceof EnumConstantAccess
}

predicate func_15(Parameter vconnected_538, PointerDereferenceExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vconnected_538
}

from Function func, Parameter vconn_538, Parameter vconnected_538, Variable vdata_540, Variable vtimeout_ms_541, Variable vinterval_ms_542, Variable vret_543, ExprStmt target_0, IfStmt target_1, ExprStmt target_2, IfStmt target_3, IfStmt target_4, DeclStmt target_5, ForStmt target_6, LabelStmt target_13, EqualityOperation target_14, PointerDereferenceExpr target_15
where
func_0(vdata_540, vtimeout_ms_541, target_0)
and func_1(vdata_540, vtimeout_ms_541, target_1)
and func_2(vconn_538, vconnected_538, vret_543, target_2)
and func_3(vret_543, target_3)
and func_4(vconnected_538, vdata_540, vret_543, target_14, target_4)
and func_5(func, target_5)
and func_6(vconnected_538, vret_543, target_6)
and func_13(func, target_13)
and func_14(target_14)
and func_15(vconnected_538, target_15)
and vconn_538.getType().hasName("connectdata *")
and vconnected_538.getType().hasName("bool *")
and vdata_540.getType().hasName("SessionHandle *")
and vtimeout_ms_541.getType().hasName("long")
and vinterval_ms_542.getType().hasName("long")
and vret_543.getType().hasName("CURLcode")
and vconn_538.getParentScope+() = func
and vconnected_538.getParentScope+() = func
and vdata_540.getParentScope+() = func
and vtimeout_ms_541.getParentScope+() = func
and vinterval_ms_542.getParentScope+() = func
and vret_543.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
