/**
 * @name wireshark-f80b7d1b279fb6c13f640019a1bbc42b18bf7469-proto_register_gsup
 * @id cpp/wireshark/f80b7d1b279fb6c13f640019a1bbc42b18bf7469/proto-register-gsup
 * @description wireshark-f80b7d1b279fb6c13f640019a1bbc42b18bf7469-epan/dissectors/packet-gsm_gsup.c-proto_register_gsup CVE-2019-10898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_774, DivExpr target_0) {
		target_0.getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_774
}

predicate func_4(Variable vei_774, VariableAccess target_4) {
		target_4.getTarget()=vei_774
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_774, DivExpr target_0, VariableAccess target_4
where
func_0(vei_774, target_0)
and func_4(vei_774, target_4)
and vei_774.getType().hasName("ei_register_info[]")
and vei_774.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
