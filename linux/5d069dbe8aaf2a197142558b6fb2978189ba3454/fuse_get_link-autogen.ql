/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_get_link
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-get-link
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_get_link 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_1327) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("is_bad_inode")
		and not target_0.getTarget().hasName("fuse_is_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_1327)
}

from Function func, Parameter vinode_1327
where
func_0(vinode_1327)
and vinode_1327.getType().hasName("inode *")
and vinode_1327.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
