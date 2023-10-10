/**
 * @name linux-1e3921471354244f70fe268586ff94a97a6dd4df-hugetlb_mcopy_atomic_pte
 * @id cpp/linux/1e3921471354244f70fe268586ff94a97a6dd4df/hugetlb-mcopy-atomic-pte
 * @description linux-1e3921471354244f70fe268586ff94a97a6dd4df-hugetlb_mcopy_atomic_pte 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof LongType
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("address_space *")
		and target_1.getExpr().(AssignExpr).getRValue() instanceof PointerFieldAccess
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned long")
		and target_2.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_2))
}

predicate func_3(Variable vvm_shared_3987, Variable vh_3988, Variable vmapping_4028) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned long")
		and target_3.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("i_size_read")
		and target_3.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="host"
		and target_3.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmapping_4028
		and target_3.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(FunctionCall).getTarget().hasName("huge_page_shift")
		and target_3.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_3988
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vvm_shared_3987)
}

predicate func_4(Variable vvm_shared_3987, Variable vret_3991) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_3991
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-14"
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vvm_shared_3987)
}

predicate func_5(Variable vvm_shared_3987, Variable vidx_4029) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vidx_4029
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_5.getThen().(GotoStmt).toString() = "goto ..."
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vvm_shared_3987)
}

predicate func_9(Parameter vdst_vma_3982) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="f_mapping"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="vm_file"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_vma_3982)
}

predicate func_10(Parameter vdst_vma_3982, Parameter vdst_addr_3983, Variable vh_3988) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("vma_hugecache_offset")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vh_3988
		and target_10.getArgument(1).(VariableAccess).getTarget()=vdst_vma_3982
		and target_10.getArgument(2).(VariableAccess).getTarget()=vdst_addr_3983)
}

predicate func_11(Function func) {
	exists(Initializer target_11 |
		target_11.getExpr() instanceof PointerFieldAccess
		and target_11.getExpr().getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Initializer target_12 |
		target_12.getExpr() instanceof FunctionCall
		and target_12.getExpr().getEnclosingFunction() = func)
}

predicate func_13(Variable vh_3988) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("pages_per_huge_page")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vh_3988)
}

predicate func_14(Parameter vdst_mm_3980, Parameter vdst_pte_3981, Variable vh_3988) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("huge_pte_lockptr")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vh_3988
		and target_14.getArgument(1).(VariableAccess).getTarget()=vdst_mm_3980
		and target_14.getArgument(2).(VariableAccess).getTarget()=vdst_pte_3981)
}

from Function func, Parameter vdst_mm_3980, Parameter vdst_pte_3981, Parameter vdst_vma_3982, Parameter vdst_addr_3983, Variable vvm_shared_3987, Variable vh_3988, Variable vret_3991, Variable vmapping_4028, Variable vidx_4029
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(vvm_shared_3987, vh_3988, vmapping_4028)
and not func_4(vvm_shared_3987, vret_3991)
and not func_5(vvm_shared_3987, vidx_4029)
and func_9(vdst_vma_3982)
and func_10(vdst_vma_3982, vdst_addr_3983, vh_3988)
and func_11(func)
and func_12(func)
and vdst_vma_3982.getType().hasName("vm_area_struct *")
and vdst_addr_3983.getType().hasName("unsigned long")
and vvm_shared_3987.getType().hasName("int")
and vh_3988.getType().hasName("hstate *")
and func_13(vh_3988)
and func_14(vdst_mm_3980, vdst_pte_3981, vh_3988)
and vret_3991.getType().hasName("int")
and vmapping_4028.getType().hasName("address_space *")
and vidx_4029.getType().hasName("unsigned long")
and vdst_mm_3980.getParentScope+() = func
and vdst_pte_3981.getParentScope+() = func
and vdst_vma_3982.getParentScope+() = func
and vdst_addr_3983.getParentScope+() = func
and vvm_shared_3987.getParentScope+() = func
and vh_3988.getParentScope+() = func
and vret_3991.getParentScope+() = func
and vmapping_4028.getParentScope+() = func
and vidx_4029.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
