/**
 * @name linux-47b0c2e4c220f2251fd8dcfbb44479819c715e15-direct_page_fault
 * @id cpp/linux/47b0c2e4c220f2251fd8dcfbb44479819c715e15/direct-page-fault
 * @description linux-47b0c2e4c220f2251fd8dcfbb44479819c715e15-direct_page_fault CVE-2022-45869
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvcpu_4223, Variable vr_4228, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_4228
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("make_mmu_pages_available")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_4223
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Variable vr_4228, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vr_4228
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vvcpu_4223, Parameter vfault_4223, Variable vis_tdp_mmu_fault_4225, Variable vr_4228) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_4228
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("kvm_tdp_mmu_map")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_4223
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfault_4223
		and target_2.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vis_tdp_mmu_fault_4225)
}

predicate func_3(Parameter vvcpu_4223, Parameter vfault_4223, Variable vis_tdp_mmu_fault_4225, Variable vr_4228) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_4228
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__direct_map")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_4223
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfault_4223
		and target_3.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vis_tdp_mmu_fault_4225)
}

from Function func, Parameter vvcpu_4223, Parameter vfault_4223, Variable vis_tdp_mmu_fault_4225, Variable vr_4228
where
func_0(vvcpu_4223, vr_4228, func)
and func_1(vr_4228, func)
and func_2(vvcpu_4223, vfault_4223, vis_tdp_mmu_fault_4225, vr_4228)
and func_3(vvcpu_4223, vfault_4223, vis_tdp_mmu_fault_4225, vr_4228)
and vvcpu_4223.getType().hasName("kvm_vcpu *")
and vfault_4223.getType().hasName("kvm_page_fault *")
and vis_tdp_mmu_fault_4225.getType().hasName("bool")
and vr_4228.getType().hasName("int")
and vvcpu_4223.getParentScope+() = func
and vfault_4223.getParentScope+() = func
and vis_tdp_mmu_fault_4225.getParentScope+() = func
and vr_4228.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
