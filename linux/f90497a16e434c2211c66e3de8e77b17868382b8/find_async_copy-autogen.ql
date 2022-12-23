/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-find_async_copy
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/find-async-copy
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-find_async_copy 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcopy_1861) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="stid"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cp_stateid"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcopy_1861)
}

from Function func, Variable vcopy_1861
where
func_0(vcopy_1861)
and vcopy_1861.getType().hasName("nfsd4_copy *")
and vcopy_1861.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
