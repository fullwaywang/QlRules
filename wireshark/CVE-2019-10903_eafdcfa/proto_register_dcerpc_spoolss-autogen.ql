/**
 * @name wireshark-eafdcfa4b6d5187a5326442a82608ab03d9dddcb-proto_register_dcerpc_spoolss
 * @id cpp/wireshark/eafdcfa4b6d5187a5326442a82608ab03d9dddcb/proto-register-dcerpc-spoolss
 * @description wireshark-eafdcfa4b6d5187a5326442a82608ab03d9dddcb-epan/dissectors/packet-dcerpc-spoolss.c-proto_register_dcerpc_spoolss CVE-2019-10903
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_8321, DivExpr target_0) {
		target_0.getValue()="10"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_8321
}

predicate func_4(Variable vei_8321, VariableAccess target_4) {
		target_4.getTarget()=vei_8321
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_8321, DivExpr target_0, VariableAccess target_4
where
func_0(vei_8321, target_0)
and func_4(vei_8321, target_4)
and vei_8321.getType().hasName("ei_register_info[]")
and vei_8321.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
