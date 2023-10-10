/**
 * @name wireshark-e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a-proto_register_nfs
 * @id cpp/wireshark/e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a/proto-register-nfs
 * @description wireshark-e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a-epan/dissectors/packet-nfs.c-proto_register_nfs CVE-2020-13164
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_14232, DivExpr target_0) {
		target_0.getValue()="5"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_14232
}

predicate func_4(Variable vei_14232, VariableAccess target_4) {
		target_4.getTarget()=vei_14232
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_14232, DivExpr target_0, VariableAccess target_4
where
func_0(vei_14232, target_0)
and func_4(vei_14232, target_4)
and vei_14232.getType().hasName("ei_register_info[]")
and vei_14232.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
