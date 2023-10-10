/**
 * @name curl-600a8cded447cd-override_login
 * @id cpp/curl/600a8cded447cd/override-login
 * @description curl-600a8cded447cd-override_login CVE-2020-8169
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vuserp_2711, Parameter vdata_2709) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_url_set")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="uh"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2709
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vuserp_2711)
}

predicate func_2(Parameter vuserp_2711, Parameter vdata_2709) {
	exists(BinaryBitwiseOperation target_2 |
		target_2.getValue()="128"
		and target_2.getLeftOperand().(Literal).getValue()="1"
		and target_2.getRightOperand().(Literal).getValue()="7"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("curl_url_set")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="uh"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2709
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vuserp_2711)
}

from Function func, Parameter vpasswdp_2711, Parameter vuserp_2711, Parameter vdata_2709
where
func_0(vuserp_2711, vdata_2709)
and not func_2(vuserp_2711, vdata_2709)
and vpasswdp_2711.getType().hasName("char **")
and vuserp_2711.getType().hasName("char **")
and vdata_2709.getType().hasName("Curl_easy *")
and vpasswdp_2711.getParentScope+() = func
and vuserp_2711.getParentScope+() = func
and vdata_2709.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
