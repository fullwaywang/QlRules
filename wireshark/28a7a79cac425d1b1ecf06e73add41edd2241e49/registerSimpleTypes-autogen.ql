/**
 * @name wireshark-28a7a79cac425d1b1ecf06e73add41edd2241e49-registerSimpleTypes
 * @id cpp/wireshark/28a7a79cac425d1b1ecf06e73add41edd2241e49/registerSimpleTypes
 * @description wireshark-28a7a79cac425d1b1ecf06e73add41edd2241e49-plugins/epan/opcua/opcua_simpletypes.c-registerSimpleTypes CVE-2018-12086
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vei_527, DivExpr target_0) {
		target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vei_527
}

predicate func_4(Variable vei_527, VariableAccess target_4) {
		target_4.getTarget()=vei_527
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_register_field_array")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof DivExpr
}

from Function func, Variable vei_527, DivExpr target_0, VariableAccess target_4
where
func_0(vei_527, target_0)
and func_4(vei_527, target_4)
and vei_527.getType().hasName("ei_register_info[]")
and vei_527.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
