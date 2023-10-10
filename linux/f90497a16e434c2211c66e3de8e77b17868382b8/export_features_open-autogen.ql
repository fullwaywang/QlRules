/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-export_features_open
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/export-features-open
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-export_features_open 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_188) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="i_private"
		and target_0.getQualifier().(VariableAccess).getTarget()=vinode_188)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

from Function func, Parameter vinode_188
where
not func_0(vinode_188)
and func_1(func)
and vinode_188.getType().hasName("inode *")
and vinode_188.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
