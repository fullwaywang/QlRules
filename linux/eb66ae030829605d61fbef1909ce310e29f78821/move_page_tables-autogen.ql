/**
 * @name linux-eb66ae030829605d61fbef1909ce310e29f78821-move_page_tables
 * @id cpp/linux/eb66ae030829605d61fbef1909ce310e29f78821/move_page_tables
 * @description linux-eb66ae030829605d61fbef1909ce310e29f78821-move_page_tables 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vvma_194) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="vm_mm"
		and target_0.getQualifier().(VariableAccess).getTarget()=vvma_194
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vvma_194, Parameter vold_addr_195, Parameter vnew_addr_196, Variable vold_end_199, Variable vold_pmd_200, Variable vnew_pmd_200, Variable vneed_flush_201) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vneed_flush_201
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("move_huge_pmd")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_194
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vold_addr_195
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_addr_196
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vold_end_199
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vold_pmd_200
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vnew_pmd_200)
}

predicate func_4(Parameter vvma_194, Parameter vold_addr_195, Parameter vlen_196, Variable vold_end_199, Variable vneed_flush_201, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(VariableAccess).getTarget()=vneed_flush_201
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("flush_tlb_mm_range")
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vold_end_199
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_196
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vold_addr_195
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_194
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Parameter vvma_194, Parameter vold_addr_195, Parameter vnew_vma_195, Parameter vnew_addr_196, Parameter vlen_196, Parameter vneed_rmap_locks_197, Variable vextent_199, Variable vold_end_199, Variable vold_pmd_200, Variable vnew_pmd_200, Variable vneed_flush_201
where
func_0(vvma_194)
and func_1(func)
and func_2(vvma_194, vold_addr_195, vnew_addr_196, vold_end_199, vold_pmd_200, vnew_pmd_200, vneed_flush_201)
and func_4(vvma_194, vold_addr_195, vlen_196, vold_end_199, vneed_flush_201, func)
and vvma_194.getType().hasName("vm_area_struct *")
and vold_addr_195.getType().hasName("unsigned long")
and vnew_vma_195.getType().hasName("vm_area_struct *")
and vnew_addr_196.getType().hasName("unsigned long")
and vlen_196.getType().hasName("unsigned long")
and vneed_rmap_locks_197.getType().hasName("bool")
and vextent_199.getType().hasName("unsigned long")
and vold_end_199.getType().hasName("unsigned long")
and vold_pmd_200.getType().hasName("pmd_t *")
and vnew_pmd_200.getType().hasName("pmd_t *")
and vneed_flush_201.getType().hasName("bool")
and vvma_194.getParentScope+() = func
and vold_addr_195.getParentScope+() = func
and vnew_vma_195.getParentScope+() = func
and vnew_addr_196.getParentScope+() = func
and vlen_196.getParentScope+() = func
and vneed_rmap_locks_197.getParentScope+() = func
and vextent_199.getParentScope+() = func
and vold_end_199.getParentScope+() = func
and vold_pmd_200.getParentScope+() = func
and vnew_pmd_200.getParentScope+() = func
and vneed_flush_201.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
