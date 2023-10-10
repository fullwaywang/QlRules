/**
 * @name wireshark-93d6b03a67953b82880cdbdcf0d30e2a3246d790-proto_register_mac_mgmt_msg_dlmap
 * @id cpp/wireshark/93d6b03a67953b82880cdbdcf0d30e2a3246d790/proto-register-mac-mgmt-msg-dlmap
 * @description wireshark-93d6b03a67953b82880cdbdcf0d30e2a3246d790-plugins/epan/wimax/msg_dlmap.c-proto_register_mac_mgmt_msg_dlmap CVE-2020-9430
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_3435, DivExpr target_0) {
		target_0.getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_3435
}

predicate func_4(Variable vei_3435, VariableAccess target_4) {
		target_4.getTarget()=vei_3435
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_3435, DivExpr target_0, VariableAccess target_4
where
func_0(vei_3435, target_0)
and func_4(vei_3435, target_4)
and vei_3435.getType().hasName("ei_register_info[]")
and vei_3435.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
