/**
 * @name freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-update_recv
 * @id cpp/freerdp/c367f65d42e0d2e1ca248998175180aa9c2eacd0/update-recv
 * @description freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-libfreerdp/core/update.c-update_recv CVE-2020-11049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(VariableAccess target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="fail"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vs_755, Parameter vupdate_755, FunctionCall target_1) {
		target_1.getTarget().hasName("update_read_synchronize")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vupdate_755
		and target_1.getArgument(1).(VariableAccess).getTarget()=vs_755
}

predicate func_2(VariableAccess target_3, Function func, ExprStmt target_2) {
		target_2.getExpr() instanceof FunctionCall
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vupdateType_758, VariableAccess target_3) {
		target_3.getTarget()=vupdateType_758
}

from Function func, Parameter vs_755, Variable vupdateType_758, Parameter vupdate_755, FunctionCall target_1, ExprStmt target_2, VariableAccess target_3
where
not func_0(target_3, func)
and func_1(vs_755, vupdate_755, target_1)
and func_2(target_3, func, target_2)
and func_3(vupdateType_758, target_3)
and vs_755.getType().hasName("wStream *")
and vupdateType_758.getType().hasName("UINT16")
and vupdate_755.getType().hasName("rdpUpdate *")
and vs_755.getParentScope+() = func
and vupdateType_758.getParentScope+() = func
and vupdate_755.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
