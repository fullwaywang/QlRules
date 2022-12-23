/**
 * @name linux-107866a8eb0b664675a260f1ba0655010fac1e08-xenvif_disconnect_queue
 * @id cpp/linux/107866a8eb0b664675a260f1ba0655010fac1e08/xenvif_disconnect_queue
 * @description linux-107866a8eb0b664675a260f1ba0655010fac1e08-xenvif_disconnect_queue CVE-2021-28691
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vqueue_683) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("put_task_struct")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="task"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_683
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="task"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_683)
}

predicate func_1(Parameter vqueue_683) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="task"
		and target_1.getQualifier().(VariableAccess).getTarget()=vqueue_683)
}

from Function func, Parameter vqueue_683
where
not func_0(vqueue_683)
and vqueue_683.getType().hasName("xenvif_queue *")
and func_1(vqueue_683)
and vqueue_683.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
