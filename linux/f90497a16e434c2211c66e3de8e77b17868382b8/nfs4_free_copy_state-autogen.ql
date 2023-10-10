/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_free_copy_state
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfs4-free-copy-state
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_free_copy_state 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcopy_1012) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="sc_type"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcopy_1012)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2531"
		and not target_1.getValue()="2615"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="2532"
		and not target_2.getValue()="2616"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vcopy_1012) {
	exists(ValueFieldAccess target_3 |
		target_3.getTarget().getName()="stid"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcopy_1012)
}

from Function func, Parameter vcopy_1012
where
func_0(vcopy_1012)
and func_1(func)
and func_2(func)
and func_3(vcopy_1012)
and vcopy_1012.getType().hasName("nfsd4_copy *")
and vcopy_1012.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
