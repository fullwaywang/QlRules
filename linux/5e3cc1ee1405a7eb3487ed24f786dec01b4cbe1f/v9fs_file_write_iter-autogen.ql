/**
 * @name linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_file_write_iter
 * @id cpp/linux/5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f/v9fs_file_write_iter
 * @description linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_file_write_iter 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter viocb_423, Variable vinode_437) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("i_size_write")
		and not target_0.getTarget().hasName("v9fs_i_size_write")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_437
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="ki_pos"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viocb_423)
}

from Function func, Parameter viocb_423, Variable vinode_437
where
func_0(viocb_423, vinode_437)
and viocb_423.getType().hasName("kiocb *")
and vinode_437.getType().hasName("inode *")
and viocb_423.getParentScope+() = func
and vinode_437.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
