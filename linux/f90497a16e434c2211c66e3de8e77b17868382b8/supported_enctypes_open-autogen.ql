/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-supported_enctypes_open
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/supported-enctypes-open
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-supported_enctypes_open 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_207) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="i_private"
		and target_0.getQualifier().(VariableAccess).getTarget()=vinode_207)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

from Function func, Parameter vinode_207
where
not func_0(vinode_207)
and func_1(func)
and vinode_207.getType().hasName("inode *")
and vinode_207.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
