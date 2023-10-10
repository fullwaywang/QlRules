/**
 * @name linux-5bfea2d9b17f1034a68147a8b03b9789af5700f9-move_page_tables
 * @id cpp/linux/5bfea2d9b17f1034a68147a8b03b9789af5700f9/move_page_tables
 * @description linux-5bfea2d9b17f1034a68147a8b03b9789af5700f9-move_page_tables CVE-2020-10757
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vold_end_245, Variable vold_pmd_247, Variable vnew_pmd_247, Variable vmoved_271, Parameter vvma_240, Parameter vold_addr_241, Parameter vnew_addr_242, Parameter vneed_rmap_locks_243, Variable vextent_245) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("pmd_devmap")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vold_pmd_247
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vextent_245
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="21"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vneed_rmap_locks_243
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("take_rmap_locks")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_240
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmoved_271
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("move_huge_pmd")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_240
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vold_addr_241
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_addr_242
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vold_end_245
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vold_pmd_247
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vnew_pmd_247)
}

predicate func_1(Variable vold_end_245, Variable vold_pmd_247, Variable vnew_pmd_247, Variable vmoved_271, Parameter vvma_240, Parameter vold_addr_241, Parameter vnew_addr_242, Parameter vneed_rmap_locks_243, Variable vextent_245) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("is_swap_pmd")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vold_pmd_247
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("pmd_trans_huge")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vold_pmd_247
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vextent_245
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="21"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vneed_rmap_locks_243
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("take_rmap_locks")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_240
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmoved_271
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("move_huge_pmd")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_240
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vold_addr_241
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_addr_242
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vold_end_245
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vold_pmd_247
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vnew_pmd_247)
}

predicate func_2(Variable vold_pmd_247) {
	exists(NotExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vold_pmd_247
		and target_2.getParent().(IfStmt).getThen().(ContinueStmt).toString() = "continue;")
}

from Function func, Variable vold_end_245, Variable vold_pmd_247, Variable vnew_pmd_247, Variable vmoved_271, Parameter vvma_240, Parameter vold_addr_241, Parameter vnew_addr_242, Parameter vneed_rmap_locks_243, Variable vextent_245
where
not func_0(vold_end_245, vold_pmd_247, vnew_pmd_247, vmoved_271, vvma_240, vold_addr_241, vnew_addr_242, vneed_rmap_locks_243, vextent_245)
and func_1(vold_end_245, vold_pmd_247, vnew_pmd_247, vmoved_271, vvma_240, vold_addr_241, vnew_addr_242, vneed_rmap_locks_243, vextent_245)
and vold_end_245.getType().hasName("unsigned long")
and vold_pmd_247.getType().hasName("pmd_t *")
and func_2(vold_pmd_247)
and vnew_pmd_247.getType().hasName("pmd_t *")
and vmoved_271.getType().hasName("bool")
and vvma_240.getType().hasName("vm_area_struct *")
and vold_addr_241.getType().hasName("unsigned long")
and vnew_addr_242.getType().hasName("unsigned long")
and vneed_rmap_locks_243.getType().hasName("bool")
and vextent_245.getType().hasName("unsigned long")
and vold_end_245.getParentScope+() = func
and vold_pmd_247.getParentScope+() = func
and vnew_pmd_247.getParentScope+() = func
and vmoved_271.getParentScope+() = func
and vvma_240.getParentScope+() = func
and vold_addr_241.getParentScope+() = func
and vnew_addr_242.getParentScope+() = func
and vneed_rmap_locks_243.getParentScope+() = func
and vextent_245.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
