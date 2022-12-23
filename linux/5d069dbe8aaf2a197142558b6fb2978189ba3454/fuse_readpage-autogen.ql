/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_readpage
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-readpage
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_readpage fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_864) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("is_bad_inode")
		and not target_0.getTarget().hasName("fuse_is_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_864)
}

from Function func, Variable vinode_864
where
func_0(vinode_864)
and vinode_864.getType().hasName("inode *")
and vinode_864.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
