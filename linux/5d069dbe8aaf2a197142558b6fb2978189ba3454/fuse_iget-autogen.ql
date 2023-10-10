/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_iget
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-iget
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_iget fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_318) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("make_bad_inode")
		and not target_0.getTarget().hasName("fuse_make_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_318)
}

from Function func, Variable vinode_318
where
func_0(vinode_318)
and vinode_318.getType().hasName("inode *")
and vinode_318.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
