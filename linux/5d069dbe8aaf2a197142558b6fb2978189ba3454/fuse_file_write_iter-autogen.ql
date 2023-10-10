/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_file_write_iter
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-file-write-iter
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_file_write_iter fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_1589) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("is_bad_inode")
		and not target_0.getTarget().hasName("fuse_is_bad")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_1589)
}

from Function func, Variable vinode_1589
where
func_0(vinode_1589)
and vinode_1589.getType().hasName("inode *")
and vinode_1589.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
