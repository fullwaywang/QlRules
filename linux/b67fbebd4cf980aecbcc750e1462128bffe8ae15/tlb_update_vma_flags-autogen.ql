/**
 * @name linux-b67fbebd4cf980aecbcc750e1462128bffe8ae15-tlb_update_vma_flags
 * @id cpp/linux/b67fbebd4cf980aecbcc750e1462128bffe8ae15/tlb-update-vma-flags
 * @description linux-b67fbebd4cf980aecbcc750e1462128bffe8ae15-tlb_update_vma_flags 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtlb_418, Parameter vvma_418, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vma_huge"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtlb_418
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("is_vm_hugetlb_page")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_418
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vtlb_418, Parameter vvma_418, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vma_exec"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtlb_418
		and target_1.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_1.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_418
		and target_1.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vtlb_418, Parameter vvma_418, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vma_pfn"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtlb_418
		and target_2.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_2.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_418
		and target_2.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_2.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="268435456"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_2))
}

from Function func, Parameter vtlb_418, Parameter vvma_418
where
not func_0(vtlb_418, vvma_418, func)
and not func_1(vtlb_418, vvma_418, func)
and not func_2(vtlb_418, vvma_418, func)
and vtlb_418.getType().hasName("mmu_gather *")
and vvma_418.getType().hasName("vm_area_struct *")
and vtlb_418.getParentScope+() = func
and vvma_418.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
