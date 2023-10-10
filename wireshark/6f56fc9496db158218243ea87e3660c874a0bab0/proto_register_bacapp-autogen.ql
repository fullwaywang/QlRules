/**
 * @name wireshark-6f56fc9496db158218243ea87e3660c874a0bab0-proto_register_bacapp
 * @id cpp/wireshark/6f56fc9496db158218243ea87e3660c874a0bab0/proto-register-bacapp
 * @description wireshark-6f56fc9496db158218243ea87e3660c874a0bab0-epan/dissectors/packet-bacapp.c-proto_register_bacapp CVE-2020-11647
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_14563, DivExpr target_0) {
		target_0.getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_14563
}

predicate func_4(Variable vei_14563, VariableAccess target_4) {
		target_4.getTarget()=vei_14563
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_14563, DivExpr target_0, VariableAccess target_4
where
func_0(vei_14563, target_0)
and func_4(vei_14563, target_4)
and vei_14563.getType().hasName("ei_register_info[]")
and vei_14563.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
