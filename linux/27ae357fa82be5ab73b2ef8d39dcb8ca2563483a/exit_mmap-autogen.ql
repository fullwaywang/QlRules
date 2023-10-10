/**
 * @name linux-27ae357fa82be5ab73b2ef8d39dcb8ca2563483a-exit_mmap
 * @id cpp/linux/27ae357fa82be5ab73b2ef8d39dcb8ca2563483a/exit_mmap
 * @description linux-27ae357fa82be5ab73b2ef8d39dcb8ca2563483a-exit_mmap CVE-2018-1000200
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vmm_3018) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mm_is_oom_victim")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_3018
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_1(Parameter vmm_3018) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("__oom_reap_task_mm")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_3018
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mm_is_oom_victim")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_3018
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_2(Parameter vmm_3018) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mm_is_oom_victim")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_3018
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_3(Parameter vmm_3018) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("mm_is_oom_victim")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vmm_3018)
}

from Function func, Parameter vmm_3018
where
not func_0(vmm_3018)
and not func_1(vmm_3018)
and not func_2(vmm_3018)
and vmm_3018.getType().hasName("mm_struct *")
and func_3(vmm_3018)
and vmm_3018.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
