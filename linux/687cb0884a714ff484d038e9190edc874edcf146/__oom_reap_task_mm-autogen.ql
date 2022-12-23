/**
 * @name linux-687cb0884a714ff484d038e9190edc874edcf146-__oom_reap_task_mm
 * @id cpp/linux/687cb0884a714ff484d038e9190edc874edcf146/--oom-reap-task-mm
 * @description linux-687cb0884a714ff484d038e9190edc874edcf146-__oom_reap_task_mm 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Variable vtlb_490, Variable vvma_491) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("unmap_page_range")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtlb_490
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvma_491
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="vm_start"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_491
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="vm_end"
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_491
		and target_4.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_4.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_491
		and target_4.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_4.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_491
		and target_4.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_6(Parameter vmm_488, Variable vtlb_490) {
	exists(UnaryMinusExpr target_6 |
		target_6.getValue()="18446744073709551615"
		and target_6.getOperand().(Literal).getValue()="1"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("tlb_gather_mmu")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtlb_490
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmm_488
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0")
}

predicate func_9(Variable vvma_491) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="vm_end"
		and target_9.getQualifier().(VariableAccess).getTarget()=vvma_491)
}

from Function func, Parameter vmm_488, Variable vtlb_490, Variable vvma_491
where
func_4(vtlb_490, vvma_491)
and func_6(vmm_488, vtlb_490)
and vmm_488.getType().hasName("mm_struct *")
and vtlb_490.getType().hasName("mmu_gather")
and vvma_491.getType().hasName("vm_area_struct *")
and func_9(vvma_491)
and vmm_488.getParentScope+() = func
and vtlb_490.getParentScope+() = func
and vvma_491.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
