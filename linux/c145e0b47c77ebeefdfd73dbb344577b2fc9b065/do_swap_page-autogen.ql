/**
 * @name linux-c145e0b47c77ebeefdfd73dbb344577b2fc9b065-do_swap_page
 * @id cpp/linux/c145e0b47c77ebeefdfd73dbb344577b2fc9b065/do_swap_page
 * @description linux-c145e0b47c77ebeefdfd73dbb344577b2fc9b065-do_swap_page CVE-2020-29374
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vpage_3503) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("reuse_swap_page")
		and not target_0.getTarget().hasName("PageKsm")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpage_3503)
}

predicate func_1(Variable vpage_3503) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("mem_cgroup_swap_full")
		and not target_1.getTarget().hasName("PageKsm")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vpage_3503)
}

predicate func_2(Variable vpage_3503) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("PageMlocked")
		and not target_2.getTarget().hasName("PageLRU")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vpage_3503)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="8192"
		and not target_3.getValue()="1"
		and target_3.getParent().(BitwiseAndExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof BitwiseAndExpr
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vpage_3503, Variable vswapcache_3503) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof BitwiseAndExpr
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpage_3503
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vswapcache_3503
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("PageKsm")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_3503
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("PageLRU")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_3503
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lru_add_drain")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vswapcache_3503)
}

predicate func_7(Parameter vvmf_3500, Variable vvma_3502, Variable vpage_3503) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("should_try_to_free_swap")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vpage_3503
		and target_7.getArgument(1).(VariableAccess).getTarget()=vvma_3502
		and target_7.getArgument(2).(PointerFieldAccess).getTarget().getName()="flags"
		and target_7.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_3500)
}

predicate func_8(Parameter vvmf_3500, Variable vvma_3502, Variable vpage_3503, Variable vswapcache_3503, Variable vpte_3506, Variable vexclusive_3508, Variable vret_3509) {
	exists(LogicalAndExpr target_8 |
		target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_3500
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("PageKsm")
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_3503
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpage_3503
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vswapcache_3503
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("page_count")
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_3503
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpte_3506
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("maybe_mkwrite")
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("pte_mkdirty")
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_3506
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvma_3502
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_3500
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_3509
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexclusive_3508
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_11(Parameter vvmf_3500, Variable vvma_3502, Variable vpte_3506, Variable vexclusive_3508, Variable vret_3509) {
	exists(BitwiseAndExpr target_11 |
		target_11.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_11.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_3500
		and target_11.getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpte_3506
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("maybe_mkwrite")
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("pte_mkdirty")
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_3506
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvma_3502
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_3500
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_3509
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexclusive_3508
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_13(Variable vvma_3502, Variable vpage_3503) {
	exists(LogicalOrExpr target_13 |
		target_13.getAnOperand() instanceof FunctionCall
		and target_13.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_13.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_3502
		and target_13.getAnOperand().(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_13.getParent().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
		and target_13.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("try_to_free_swap")
		and target_13.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_3503)
}

predicate func_14(Parameter vvmf_3500) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="(unknown field)"
		and target_14.getQualifier().(VariableAccess).getTarget()=vvmf_3500)
}

predicate func_16(Variable vvma_3502, Variable vpage_3503, Variable vvmemmap_base) {
	exists(PointerArithmeticOperation target_16 |
		target_16.getLeftOperand().(VariableAccess).getTarget()=vpage_3503
		and target_16.getRightOperand().(VariableAccess).getTarget()=vvmemmap_base
		and target_16.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pfn_pte")
		and target_16.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="vm_page_prot"
		and target_16.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_3502)
}

predicate func_17(Parameter vvmf_3500, Variable vvma_3502, Variable vpage_3503, Variable vexclusive_3508) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("do_page_add_anon_rmap")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vpage_3503
		and target_17.getArgument(1).(VariableAccess).getTarget()=vvma_3502
		and target_17.getArgument(2).(ValueFieldAccess).getTarget().getName()="address"
		and target_17.getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_17.getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmf_3500
		and target_17.getArgument(3).(VariableAccess).getTarget()=vexclusive_3508)
}

predicate func_18(Variable vpage_3503, Variable vswapcache_3503) {
	exists(AssignExpr target_18 |
		target_18.getLValue().(VariableAccess).getTarget()=vpage_3503
		and target_18.getRValue().(VariableAccess).getTarget()=vswapcache_3503)
}

predicate func_19(Variable vpage_3503, Variable vswapcache_3503) {
	exists(LogicalAndExpr target_19 |
		target_19.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpage_3503
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vswapcache_3503
		and target_19.getAnOperand().(VariableAccess).getTarget()=vswapcache_3503)
}

from Function func, Parameter vvmf_3500, Variable vvma_3502, Variable vpage_3503, Variable vswapcache_3503, Variable vpte_3506, Variable vexclusive_3508, Variable vret_3509, Variable vvmemmap_base
where
func_0(vpage_3503)
and func_1(vpage_3503)
and func_2(vpage_3503)
and func_3(func)
and not func_4(vpage_3503, vswapcache_3503)
and not func_7(vvmf_3500, vvma_3502, vpage_3503)
and not func_8(vvmf_3500, vvma_3502, vpage_3503, vswapcache_3503, vpte_3506, vexclusive_3508, vret_3509)
and func_11(vvmf_3500, vvma_3502, vpte_3506, vexclusive_3508, vret_3509)
and func_13(vvma_3502, vpage_3503)
and vvmf_3500.getType().hasName("vm_fault *")
and func_14(vvmf_3500)
and vvma_3502.getType().hasName("vm_area_struct *")
and vpage_3503.getType().hasName("page *")
and func_16(vvma_3502, vpage_3503, vvmemmap_base)
and func_17(vvmf_3500, vvma_3502, vpage_3503, vexclusive_3508)
and vswapcache_3503.getType().hasName("page *")
and func_18(vpage_3503, vswapcache_3503)
and func_19(vpage_3503, vswapcache_3503)
and vpte_3506.getType().hasName("pte_t")
and vexclusive_3508.getType().hasName("int")
and vret_3509.getType().hasName("vm_fault_t")
and vvmemmap_base.getType().hasName("unsigned long")
and vvmf_3500.getParentScope+() = func
and vvma_3502.getParentScope+() = func
and vpage_3503.getParentScope+() = func
and vswapcache_3503.getParentScope+() = func
and vpte_3506.getParentScope+() = func
and vexclusive_3508.getParentScope+() = func
and vret_3509.getParentScope+() = func
and not vvmemmap_base.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
