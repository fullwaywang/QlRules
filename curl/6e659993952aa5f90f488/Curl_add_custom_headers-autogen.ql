/**
 * @name curl-6e659993952aa5f90f488-Curl_add_custom_headers
 * @id cpp/curl/6e659993952aa5f90f488/Curl-add-custom-headers
 * @description curl-6e659993952aa5f90f488-Curl_add_custom_headers CVE-2022-27776
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_1777) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("allow_auth_to_host")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata_1777)
}

predicate func_2(Variable vcompare_1875, Variable vconn_1786, Parameter vdata_1777) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="this_is_a_follow"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1777
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="first_host"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1777
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="allow_auth_to_other_hosts"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1777
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_strcasecompare")
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="first_host"
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1777
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="host"
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1786
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompare_1875
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Authorization:"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Authorization:"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompare_1875
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Cookie:"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Cookie:"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(EmptyStmt).toString() = ";")
}

from Function func, Variable vcompare_1875, Variable vconn_1786, Parameter vdata_1777
where
not func_0(vdata_1777)
and func_2(vcompare_1875, vconn_1786, vdata_1777)
and vcompare_1875.getType().hasName("char *")
and vconn_1786.getType().hasName("connectdata *")
and vdata_1777.getType().hasName("Curl_easy *")
and vcompare_1875.getParentScope+() = func
and vconn_1786.getParentScope+() = func
and vdata_1777.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
