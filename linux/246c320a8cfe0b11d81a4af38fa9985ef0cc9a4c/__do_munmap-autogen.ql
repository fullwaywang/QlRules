/**
 * @name linux-246c320a8cfe0b11d81a4af38fa9985ef0cc9a4c-__do_munmap
 * @id cpp/linux/246c320a8cfe0b11d81a4af38fa9985ef0cc9a4c/__do_munmap
 * @description linux-246c320a8cfe0b11d81a4af38fa9985ef0cc9a4c-__do_munmap 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vmm_2732, Parameter vdowngrade_2733, Variable vend_2735, Variable vvma_2736, Variable vprev_2736, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("detach_vmas_to_be_unmapped")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_2732
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvma_2736
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprev_2736
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vend_2735
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdowngrade_2733
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0))
}

predicate func_6(Parameter vmm_2732, Variable vend_2735, Variable vvma_2736, Variable vprev_2736) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("detach_vmas_to_be_unmapped")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vmm_2732
		and target_6.getArgument(1).(VariableAccess).getTarget()=vvma_2736
		and target_6.getArgument(2).(VariableAccess).getTarget()=vprev_2736
		and target_6.getArgument(3).(VariableAccess).getTarget()=vend_2735)
}

predicate func_7(Parameter vmm_2732, Parameter vdowngrade_2733, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(VariableAccess).getTarget()=vdowngrade_2733
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mmap_write_downgrade")
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_2732
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

from Function func, Parameter vmm_2732, Parameter vdowngrade_2733, Variable vend_2735, Variable vvma_2736, Variable vprev_2736
where
not func_0(vmm_2732, vdowngrade_2733, vend_2735, vvma_2736, vprev_2736, func)
and func_6(vmm_2732, vend_2735, vvma_2736, vprev_2736)
and vmm_2732.getType().hasName("mm_struct *")
and vdowngrade_2733.getType().hasName("bool")
and func_7(vmm_2732, vdowngrade_2733, func)
and vend_2735.getType().hasName("unsigned long")
and vvma_2736.getType().hasName("vm_area_struct *")
and vprev_2736.getType().hasName("vm_area_struct *")
and vmm_2732.getParentScope+() = func
and vdowngrade_2733.getParentScope+() = func
and vend_2735.getParentScope+() = func
and vvma_2736.getParentScope+() = func
and vprev_2736.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
