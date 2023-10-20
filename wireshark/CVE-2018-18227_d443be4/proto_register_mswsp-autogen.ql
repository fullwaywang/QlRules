/**
 * @name wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-proto_register_mswsp
 * @id cpp/wireshark/d443be449a52f95df5754adc39e1f3472fec2f03/proto-register-mswsp
 * @description wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-epan/dissectors/packet-mswsp.c-proto_register_mswsp CVE-2018-18227
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_8022, DivExpr target_0) {
		target_0.getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_8022
}

predicate func_4(Variable vei_8022, VariableAccess target_4) {
		target_4.getTarget()=vei_8022
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_8022, DivExpr target_0, VariableAccess target_4
where
func_0(vei_8022, target_0)
and func_4(vei_8022, target_4)
and vei_8022.getType().hasName("ei_register_info[]")
and vei_8022.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
