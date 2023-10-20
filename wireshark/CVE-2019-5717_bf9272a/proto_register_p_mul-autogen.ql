/**
 * @name wireshark-bf9272a92f3df1e4ccfaad434e123222ae5313f7-proto_register_p_mul
 * @id cpp/wireshark/bf9272a92f3df1e4ccfaad434e123222ae5313f7/proto-register-p-mul
 * @description wireshark-bf9272a92f3df1e4ccfaad434e123222ae5313f7-epan/dissectors/packet-p_mul.c-proto_register_p_mul CVE-2019-5717
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_1539, DivExpr target_0) {
		target_0.getValue()="13"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_1539
}

predicate func_4(Variable vei_1539, VariableAccess target_4) {
		target_4.getTarget()=vei_1539
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_1539, DivExpr target_0, VariableAccess target_4
where
func_0(vei_1539, target_0)
and func_4(vei_1539, target_4)
and vei_1539.getType().hasName("ei_register_info[]")
and vei_1539.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
