/**
 * @name linux-b90cd6f2b905905fb42671009dc0e27c310a16ae-smp_task_timedout
 * @id cpp/linux/b90cd6f2b905905fb42671009dc0e27c310a16ae/smp_task_timedout
 * @description linux-b90cd6f2b905905fb42671009dc0e27c310a16ae-smp_task_timedout 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vtask_47) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="task_state_flags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtask_47
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="4"
		and target_0.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="task_state_flags"
		and target_0.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtask_47
		and target_0.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2")
}

predicate func_1(Variable vtask_47, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("complete")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="completion"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="slow_task"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtask_47
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Variable vtask_47
where
func_0(vtask_47)
and func_1(vtask_47, func)
and vtask_47.getType().hasName("sas_task *")
and vtask_47.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
