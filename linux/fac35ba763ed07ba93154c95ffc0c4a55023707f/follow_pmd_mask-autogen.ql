/**
 * @name linux-fac35ba763ed07ba93154c95ffc0c4a55023707f-follow_pmd_mask
 * @id cpp/linux/fac35ba763ed07ba93154c95ffc0c4a55023707f/follow_pmd_mask
 * @description linux-fac35ba763ed07ba93154c95ffc0c4a55023707f-follow_pmd_mask 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vaddress_647, Parameter vflags_648, Variable vpmd_651, Variable vmm_654) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("follow_huge_pmd")
		and not target_0.getTarget().hasName("follow_huge_pmd_pte")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vmm_654
		and target_0.getArgument(1).(VariableAccess).getTarget()=vaddress_647
		and target_0.getArgument(2).(VariableAccess).getTarget()=vpmd_651
		and target_0.getArgument(3).(VariableAccess).getTarget()=vflags_648)
}

from Function func, Parameter vaddress_647, Parameter vflags_648, Variable vpmd_651, Variable vmm_654
where
func_0(vaddress_647, vflags_648, vpmd_651, vmm_654)
and vaddress_647.getType().hasName("unsigned long")
and vflags_648.getType().hasName("unsigned int")
and vpmd_651.getType().hasName("pmd_t *")
and vmm_654.getType().hasName("mm_struct *")
and vaddress_647.getParentScope+() = func
and vflags_648.getParentScope+() = func
and vpmd_651.getParentScope+() = func
and vmm_654.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
