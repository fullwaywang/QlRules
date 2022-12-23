/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_fsync
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-fsync
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_fsync fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_540) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("is_bad_inode")
		and not target_0.getTarget().hasName("fuse_is_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_540)
}

from Function func, Variable vinode_540
where
func_0(vinode_540)
and vinode_540.getType().hasName("inode *")
and vinode_540.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
