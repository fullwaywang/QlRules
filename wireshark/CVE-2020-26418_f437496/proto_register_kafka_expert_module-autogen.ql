/**
 * @name wireshark-f4374967bbf9c12746b8ec3cd54dddada9dd353e-proto_register_kafka_expert_module
 * @id cpp/wireshark/f4374967bbf9c12746b8ec3cd54dddada9dd353e/proto-register-kafka-expert-module
 * @description wireshark-f4374967bbf9c12746b8ec3cd54dddada9dd353e-epan/dissectors/packet-kafka.c-proto_register_kafka_expert_module CVE-2020-26418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_10226, DivExpr target_0) {
		target_0.getValue()="11"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_10226
}

predicate func_4(Variable vei_10226, VariableAccess target_4) {
		target_4.getTarget()=vei_10226
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_10226, DivExpr target_0, VariableAccess target_4
where
func_0(vei_10226, target_0)
and func_4(vei_10226, target_4)
and vei_10226.getType().hasName("ei_register_info[]")
and vei_10226.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
