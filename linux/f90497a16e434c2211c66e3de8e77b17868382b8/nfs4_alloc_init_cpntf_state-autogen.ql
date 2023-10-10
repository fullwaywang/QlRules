/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_alloc_init_cpntf_state
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfs4-alloc-init-cpntf-state
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_alloc_init_cpntf_state 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcps_994) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="sc_count"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcps_994)
}

from Function func, Variable vcps_994
where
func_0(vcps_994)
and vcps_994.getType().hasName("nfs4_cpntf_state *")
and vcps_994.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
