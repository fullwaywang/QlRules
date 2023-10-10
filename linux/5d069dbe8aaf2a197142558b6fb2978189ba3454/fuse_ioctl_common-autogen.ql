/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_ioctl_common
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-ioctl-common
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_ioctl_common fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_2969) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("is_bad_inode")
		and not target_0.getTarget().hasName("fuse_is_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_2969)
}

from Function func, Variable vinode_2969
where
func_0(vinode_2969)
and vinode_2969.getType().hasName("inode *")
and vinode_2969.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
