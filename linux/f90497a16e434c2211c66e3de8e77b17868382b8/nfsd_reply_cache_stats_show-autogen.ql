/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_reply_cache_stats_show
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-reply-cache-stats-show
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_reply_cache_stats_show 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vm_607) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="private"
		and target_0.getQualifier().(VariableAccess).getTarget()=vm_607)
}

predicate func_1(Parameter vm_607) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("net_generic")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="s_fs_info"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="i_sb"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("file_inode")
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="file"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_607
		and target_1.getArgument(1).(VariableAccess).getType().hasName("unsigned int"))
}

from Function func, Parameter vm_607
where
func_0(vm_607)
and not func_1(vm_607)
and vm_607.getType().hasName("seq_file *")
and vm_607.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
