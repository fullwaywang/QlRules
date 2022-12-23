/**
 * @name linux-973c096f6a85e5b5f2a295126ba6928d9a6afd45-vgacon_scroll
 * @id cpp/linux/973c096f6a85e5b5f2a295126ba6928d9a6afd45/vgacon_scroll
 * @description linux-973c096f6a85e5b5f2a295126ba6928d9a6afd45-vgacon_scroll 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vt_1373, Parameter vdir_1374, Parameter vlines_1374, Parameter vc_1373) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("vgacon_scrollback_update")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1373
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vt_1373
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlines_1374
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdir_1374)
}

from Function func, Parameter vt_1373, Parameter vdir_1374, Parameter vlines_1374, Parameter vc_1373
where
func_0(vt_1373, vdir_1374, vlines_1374, vc_1373)
and vt_1373.getType().hasName("unsigned int")
and vdir_1374.getType().hasName("con_scroll")
and vlines_1374.getType().hasName("unsigned int")
and vc_1373.getType().hasName("vc_data *")
and vt_1373.getParentScope+() = func
and vdir_1374.getParentScope+() = func
and vlines_1374.getParentScope+() = func
and vc_1373.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
