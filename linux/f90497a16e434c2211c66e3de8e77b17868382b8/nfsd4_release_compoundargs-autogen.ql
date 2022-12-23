/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_release_compoundargs
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-release-compoundargs
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_release_compoundargs 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vargs_5394) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kfree")
		and not target_0.getTarget().hasName("vfree")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="ops"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_5394)
}

from Function func, Variable vargs_5394
where
func_0(vargs_5394)
and vargs_5394.getType().hasName("nfsd4_compoundargs *")
and vargs_5394.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
