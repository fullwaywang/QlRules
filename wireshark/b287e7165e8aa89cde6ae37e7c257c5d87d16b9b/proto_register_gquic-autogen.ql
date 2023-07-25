/**
 * @name wireshark-b287e7165e8aa89cde6ae37e7c257c5d87d16b9b-proto_register_gquic
 * @id cpp/wireshark/b287e7165e8aa89cde6ae37e7c257c5d87d16b9b/proto-register-gquic
 * @description wireshark-b287e7165e8aa89cde6ae37e7c257c5d87d16b9b-epan/dissectors/packet-gquic.c-proto_register_gquic CVE-2020-28030
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_3171, DivExpr target_0) {
		target_0.getValue()="5"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_3171
}

predicate func_4(Variable vei_3171, VariableAccess target_4) {
		target_4.getTarget()=vei_3171
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_3171, DivExpr target_0, VariableAccess target_4
where
func_0(vei_3171, target_0)
and func_4(vei_3171, target_4)
and vei_3171.getType().hasName("ei_register_info[]")
and vei_3171.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
