/**
 * @name wireshark-3ff940652962c099b73ae3233322b8697b0d10ab-proto_register_fb_zero
 * @id cpp/wireshark/3ff940652962c099b73ae3233322b8697b0d10ab/proto-register-fb-zero
 * @description wireshark-3ff940652962c099b73ae3233322b8697b0d10ab-epan/dissectors/packet-fbzero.c-proto_register_fb_zero CVE-2020-26575
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_561, DivExpr target_0) {
		target_0.getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_561
}

predicate func_4(Variable vei_561, VariableAccess target_4) {
		target_4.getTarget()=vei_561
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_561, DivExpr target_0, VariableAccess target_4
where
func_0(vei_561, target_0)
and func_4(vei_561, target_4)
and vei_561.getType().hasName("ei_register_info[]")
and vei_561.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
