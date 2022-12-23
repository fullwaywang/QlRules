/**
 * @name linux-9f46c187e2e680ecd9de7983e4d081c3391acc76-kvm_mmu_invpcid_gva
 * @id cpp/linux/9f46c187e2e680ecd9de7983e4d081c3391acc76/kvm_mmu_invpcid_gva
 * @description linux-9f46c187e2e680ecd9de7983e4d081c3391acc76-kvm_mmu_invpcid_gva CVE-2022-1789
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vtlb_flush_5469, Variable vmmu_5468) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof LogicalAndExpr
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="invlpg"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmu_5468
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen() instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtlb_flush_5469)
}

predicate func_3(Parameter vgva_5466, Parameter vpcid_5466, Variable vmmu_5468, Parameter vvcpu_5466) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="invlpg"
		and target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmu_5468
		and target_3.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_5466
		and target_3.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vgva_5466
		and target_3.getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="hpa"
		and target_3.getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="root"
		and target_3.getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmu_5468
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpcid_5466
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("kvm_get_active_pcid")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_5466)
}

predicate func_6(Variable vmmu_5468) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="root"
		and target_6.getQualifier().(VariableAccess).getTarget()=vmmu_5468)
}

predicate func_7(Variable vmmu_5468) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="prev_roots"
		and target_7.getQualifier().(VariableAccess).getTarget()=vmmu_5468)
}

from Function func, Variable vtlb_flush_5469, Variable vi_5470, Parameter vgva_5466, Parameter vpcid_5466, Variable vmmu_5468, Parameter vvcpu_5466
where
not func_1(vtlb_flush_5469, vmmu_5468)
and func_3(vgva_5466, vpcid_5466, vmmu_5468, vvcpu_5466)
and vtlb_flush_5469.getType().hasName("bool")
and vi_5470.getType().hasName("uint")
and vgva_5466.getType().hasName("gva_t")
and vpcid_5466.getType().hasName("unsigned long")
and vmmu_5468.getType().hasName("kvm_mmu *")
and func_6(vmmu_5468)
and func_7(vmmu_5468)
and vvcpu_5466.getType().hasName("kvm_vcpu *")
and vtlb_flush_5469.getParentScope+() = func
and vi_5470.getParentScope+() = func
and vgva_5466.getParentScope+() = func
and vpcid_5466.getParentScope+() = func
and vmmu_5468.getParentScope+() = func
and vvcpu_5466.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
