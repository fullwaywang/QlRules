/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_copy
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-copy
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_copy 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcopy_1794) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="stid"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcopy_1794)
}

from Function func, Variable vcopy_1794
where
func_0(vcopy_1794)
and vcopy_1794.getType().hasName("nfsd4_copy *")
and vcopy_1794.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
