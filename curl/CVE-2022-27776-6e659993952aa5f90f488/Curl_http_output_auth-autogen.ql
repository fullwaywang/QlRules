/**
 * @name curl-6e659993952aa5f90f488-Curl_http_output_auth
 * @id cpp/curl/6e659993952aa5f90f488/Curl-http-output-auth
 * @description curl-6e659993952aa5f90f488-Curl_http_output_auth CVE-2022-27776
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_793) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("allow_auth_to_host")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata_793)
}

predicate func_1(Parameter vconn_794) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="netrc"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_794)
}

predicate func_2(Parameter vconn_794, Parameter vrequest_795, Parameter vpath_797, Variable vresult_801, Variable vauthhost_802, Parameter vdata_793) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_801
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("output_auth_headers")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_793
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_794
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vauthhost_802
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vrequest_795
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpath_797
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof FunctionCall)
}

predicate func_4(Parameter vconn_794, Parameter vdata_793) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="this_is_a_follow"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_793
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof ValueFieldAccess
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="first_host"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_793
		and target_4.getAnOperand().(ValueFieldAccess).getTarget().getName()="allow_auth_to_other_hosts"
		and target_4.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_4.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_793
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_strcasecompare")
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="first_host"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_793
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="host"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_794
		and target_4.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt)
}

from Function func, Parameter vconn_794, Parameter vrequest_795, Parameter vpath_797, Variable vresult_801, Variable vauthhost_802, Parameter vdata_793
where
not func_0(vdata_793)
and func_1(vconn_794)
and func_2(vconn_794, vrequest_795, vpath_797, vresult_801, vauthhost_802, vdata_793)
and func_4(vconn_794, vdata_793)
and vconn_794.getType().hasName("connectdata *")
and vrequest_795.getType().hasName("const char *")
and vpath_797.getType().hasName("const char *")
and vresult_801.getType().hasName("CURLcode")
and vauthhost_802.getType().hasName("auth *")
and vdata_793.getType().hasName("Curl_easy *")
and vconn_794.getParentScope+() = func
and vrequest_795.getParentScope+() = func
and vpath_797.getParentScope+() = func
and vresult_801.getParentScope+() = func
and vauthhost_802.getParentScope+() = func
and vdata_793.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
