/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-manage_cpntf_state
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/manage-cpntf-state
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-manage_cpntf_state 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstate_6265) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="sc_type"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_6265)
}

predicate func_1(Variable vstate_6265) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="sc_count"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_6265)
}

from Function func, Variable vstate_6265
where
func_0(vstate_6265)
and func_1(vstate_6265)
and vstate_6265.getType().hasName("nfs4_cpntf_state *")
and vstate_6265.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
