/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_evict_inode
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-evict-inode
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_evict_inode fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_118) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("is_bad_inode")
		and not target_0.getTarget().hasName("fuse_is_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_118)
}

from Function func, Parameter vinode_118
where
func_0(vinode_118)
and vinode_118.getType().hasName("inode *")
and vinode_118.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
