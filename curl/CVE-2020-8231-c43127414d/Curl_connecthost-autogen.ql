/**
 * @name curl-c43127414d-Curl_connecthost
 * @id cpp/curl/c43127414d/Curl-connecthost
 * @description curl-c43127414d-lib/connect.c-Curl_connecthost CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vconn_1024, Variable vdata_1030, ConditionalExpr target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1030
		and target_1.getThen() instanceof Literal
		and target_1.getElse().(PointerFieldAccess).getTarget().getName()="timeoutms_per_addr"
		and target_1.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1024
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("singleipconnect")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1024
}

from Function func, Parameter vconn_1024, Variable vdata_1030, ConditionalExpr target_1
where
func_1(vconn_1024, vdata_1030, target_1)
and vconn_1024.getType().hasName("connectdata *")
and vdata_1030.getType().hasName("SessionHandle *")
and vconn_1024.getParentScope+() = func
and vdata_1030.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
