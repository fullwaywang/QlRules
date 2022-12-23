/**
 * @name linux-973c096f6a85e5b5f2a295126ba6928d9a6afd45-vgacon_switch
 * @id cpp/linux/973c096f6a85e5b5f2a295126ba6928d9a6afd45/vgacon_switch
 * @description linux-973c096f6a85e5b5f2a295126ba6928d9a6afd45-vgacon_switch 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_843, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("vgacon_scrollback_switch")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vc_num"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_843
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vc_843
where
func_0(vc_843, func)
and vc_843.getType().hasName("vc_data *")
and vc_843.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
