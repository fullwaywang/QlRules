/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_do_getattr
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-do-getattr
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_do_getattr fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_1005) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("make_bad_inode")
		and not target_0.getTarget().hasName("fuse_make_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_1005)
}

from Function func, Parameter vinode_1005
where
func_0(vinode_1005)
and vinode_1005.getType().hasName("inode *")
and vinode_1005.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
