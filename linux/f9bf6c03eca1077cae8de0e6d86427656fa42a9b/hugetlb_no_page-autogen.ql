/**
 * @name linux-f9bf6c03eca1077cae8de0e6d86427656fa42a9b-hugetlb_no_page
 * @id cpp/linux/f9bf6c03eca1077cae8de0e6d86427656fa42a9b/hugetlb-no-page
 * @description linux-f9bf6c03eca1077cae8de0e6d86427656fa42a9b-hugetlb_no_page 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vptep_5558, Variable vh_5561, Variable vpage_5565, Variable vptl_5567, Parameter vmm_5555) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptl_5567
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("huge_pte_lock")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_5561
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmm_5555
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vptep_5558
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_5565)
}

predicate func_2(Variable vret_5562, Variable vpage_5565) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_5562
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_5565)
}

predicate func_3(Parameter vptep_5558) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("huge_ptep_get")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vptep_5558)
}

predicate func_4(Variable vpage_5565, Variable vptl_5567) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptl_5567
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_5565)
}

predicate func_8(Function func) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("huge_pte_none")
		and target_8.getArgument(0) instanceof FunctionCall
		and target_8.getEnclosingFunction() = func)
}

predicate func_11(Parameter vptep_5558, Parameter vold_pte_5559, Variable vh_5561, Parameter vmm_5555) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("hugetlb_pte_stable")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vh_5561
		and target_11.getArgument(1).(VariableAccess).getTarget()=vmm_5555
		and target_11.getArgument(2).(VariableAccess).getTarget()=vptep_5558
		and target_11.getArgument(3).(VariableAccess).getTarget()=vold_pte_5559)
}

from Function func, Parameter vptep_5558, Parameter vold_pte_5559, Variable vh_5561, Variable vret_5562, Variable vpage_5565, Variable vptl_5567, Parameter vmm_5555
where
func_1(vptep_5558, vh_5561, vpage_5565, vptl_5567, vmm_5555)
and func_2(vret_5562, vpage_5565)
and func_3(vptep_5558)
and func_4(vpage_5565, vptl_5567)
and func_8(func)
and vptep_5558.getType().hasName("pte_t *")
and vold_pte_5559.getType().hasName("pte_t")
and func_11(vptep_5558, vold_pte_5559, vh_5561, vmm_5555)
and vh_5561.getType().hasName("hstate *")
and vret_5562.getType().hasName("vm_fault_t")
and vpage_5565.getType().hasName("page *")
and vptl_5567.getType().hasName("spinlock_t *")
and vmm_5555.getType().hasName("mm_struct *")
and vptep_5558.getParentScope+() = func
and vold_pte_5559.getParentScope+() = func
and vh_5561.getParentScope+() = func
and vret_5562.getParentScope+() = func
and vpage_5565.getParentScope+() = func
and vptl_5567.getParentScope+() = func
and vmm_5555.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
