/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_copy_notify
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-copy-notify
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_copy_notify 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcps_1903) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="stid"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcps_1903)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2489"
		and not target_1.getValue()="2573"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="2490"
		and not target_2.getValue()="2574"
		and target_2.getEnclosingFunction() = func)
}

from Function func, Variable vcps_1903
where
func_0(vcps_1903)
and func_1(func)
and func_2(func)
and vcps_1903.getType().hasName("nfs4_cpntf_state *")
and vcps_1903.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
