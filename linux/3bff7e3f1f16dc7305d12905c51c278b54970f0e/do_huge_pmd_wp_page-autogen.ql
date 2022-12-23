/**
 * @name linux-3bff7e3f1f16dc7305d12905c51c278b54970f0e-do_huge_pmd_wp_page
 * @id cpp/linux/3bff7e3f1f16dc7305d12905c51c278b54970f0e/do_huge_pmd_wp_page
 * @description linux-3bff7e3f1f16dc7305d12905c51c278b54970f0e-do_huge_pmd_wp_page CVE-2020-29374
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vpage_1286) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("reuse_swap_page")
		and not target_0.getTarget().hasName("PageSwapCache")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpage_1286)
}

predicate func_3(Variable vpage_1286, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(FunctionCall).getTarget().hasName("PageSwapCache")
		and target_3.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_1286
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("try_to_free_swap")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_1286
		and func.getEntryPoint().(BlockStmt).getStmt(13)=target_3)
}

predicate func_4(Parameter vvmf_1283, Variable vvma_1285, Variable vpage_1286, Variable vhaddr_1287, Variable vorig_pmd_1288, Variable ventry_1326, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("page_count")
		and target_4.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_1286
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventry_1326
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pmd_mkyoung")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorig_pmd_1288
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventry_1326
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("maybe_pmd_mkwrite")
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("pmd_mkdirty")
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ventry_1326
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvma_1285
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("pmdp_set_access_flags")
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_1285
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhaddr_1287
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pmd"
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_1283
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=ventry_1326
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("update_mmu_cache_pmd")
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_1285
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="address"
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_1283
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pmd"
		and target_4.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_1283
		and target_4.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("unlock_page")
		and target_4.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_1286
		and target_4.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_4.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptl"
		and target_4.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_1283
		and func.getEntryPoint().(BlockStmt).getStmt(14)=target_4)
}

predicate func_5(Function func) {
	exists(LabelStmt target_5 |
		target_5.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getStmt(18)=target_5)
}

predicate func_6(Variable vpage_1286) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("put_page")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vpage_1286)
}

predicate func_7(Variable vpage_1286) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("unlock_page")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vpage_1286)
}

from Function func, Parameter vvmf_1283, Variable vvma_1285, Variable vpage_1286, Variable vhaddr_1287, Variable vorig_pmd_1288, Variable ventry_1326
where
func_0(vpage_1286)
and not func_3(vpage_1286, func)
and not func_4(vvmf_1283, vvma_1285, vpage_1286, vhaddr_1287, vorig_pmd_1288, ventry_1326, func)
and not func_5(func)
and vvmf_1283.getType().hasName("vm_fault *")
and vvma_1285.getType().hasName("vm_area_struct *")
and vpage_1286.getType().hasName("page *")
and func_6(vpage_1286)
and func_7(vpage_1286)
and vhaddr_1287.getType().hasName("unsigned long")
and vorig_pmd_1288.getType().hasName("pmd_t")
and ventry_1326.getType().hasName("pmd_t")
and vvmf_1283.getParentScope+() = func
and vvma_1285.getParentScope+() = func
and vpage_1286.getParentScope+() = func
and vhaddr_1287.getParentScope+() = func
and vorig_pmd_1288.getParentScope+() = func
and ventry_1326.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
