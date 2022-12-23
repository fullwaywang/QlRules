/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_do_setattr
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-do-setattr
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_do_setattr fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_1575) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("make_bad_inode")
		and not target_0.getTarget().hasName("fuse_make_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_1575)
}

from Function func, Variable vinode_1575
where
func_0(vinode_1575)
and vinode_1575.getType().hasName("inode *")
and vinode_1575.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
