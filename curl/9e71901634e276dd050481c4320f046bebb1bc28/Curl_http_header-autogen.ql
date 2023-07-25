/**
 * @name curl-9e71901634e276dd050481c4320f046bebb1bc28-Curl_http_header
 * @id cpp/curl/9e71901634e276dd050481c4320f046bebb1bc28/Curl-http-header
 * @description curl-9e71901634e276dd050481c4320f046bebb1bc28-lib/http.c-Curl_http_header CVE-2022-43551
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_3368, ExprStmt target_3, ValueFieldAccess target_0) {
		target_0.getTarget().getName()="hostname"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="up"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3368
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Parameter vconn_3368, LogicalAndExpr target_4, LogicalAndExpr target_5) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="host"
		and target_1.getQualifier().(VariableAccess).getTarget()=vconn_3368
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdata_3368, ExprStmt target_3, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="state"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdata_3368
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_3(Parameter vdata_3368, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_3368
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Illegal STS header skipped"
}

predicate func_4(Parameter vconn_3368, Parameter vdata_3368, LogicalAndExpr target_4) {
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="hsts"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3368
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Strict-Transport-Security:"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="26"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3368
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vconn_3368, Parameter vdata_3368, LogicalAndExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="asi"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3368
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Alt-Svc:"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="8"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3368
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vconn_3368, Parameter vdata_3368, ValueFieldAccess target_0, PointerFieldAccess target_2, ExprStmt target_3, LogicalAndExpr target_4, LogicalAndExpr target_5
where
func_0(vdata_3368, target_3, target_0)
and not func_1(vconn_3368, target_4, target_5)
and func_2(vdata_3368, target_3, target_2)
and func_3(vdata_3368, target_3)
and func_4(vconn_3368, vdata_3368, target_4)
and func_5(vconn_3368, vdata_3368, target_5)
and vconn_3368.getType().hasName("connectdata *")
and vdata_3368.getType().hasName("Curl_easy *")
and vconn_3368.getParentScope+() = func
and vdata_3368.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
