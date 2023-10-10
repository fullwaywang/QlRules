/**
 * @name linux-be83bbf806822b1b89e0a0f23cd87cddc409e429-do_mmap
 * @id cpp/linux/be83bbf806822b1b89e0a0f23cd87cddc409e429/do_mmap
 * @description linux-be83bbf806822b1b89e0a0f23cd87cddc409e429-do_mmap 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vfile_1330, Parameter vlen_1331, Parameter vpgoff_1333, Variable vinode_1409) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("file_mmap_ok")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfile_1330
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinode_1409
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpgoff_1333
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlen_1331
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="18446744073709551541"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="75"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vfile_1330)
}

predicate func_1(Parameter vfile_1330) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("file_inode")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vfile_1330)
}

predicate func_2(Parameter vlen_1331, Parameter vvm_flags_1332, Variable vmm_1336) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("mlock_future_check")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vmm_1336
		and target_2.getArgument(1).(VariableAccess).getTarget()=vvm_flags_1332
		and target_2.getArgument(2).(VariableAccess).getTarget()=vlen_1331)
}

predicate func_3(Parameter vfile_1330, Parameter vaddr_1330, Parameter vlen_1331, Parameter vflags_1332, Parameter vpgoff_1333) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("get_unmapped_area")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vfile_1330
		and target_3.getArgument(1).(VariableAccess).getTarget()=vaddr_1330
		and target_3.getArgument(2).(VariableAccess).getTarget()=vlen_1331
		and target_3.getArgument(3).(VariableAccess).getTarget()=vpgoff_1333
		and target_3.getArgument(4).(VariableAccess).getTarget()=vflags_1332)
}

from Function func, Parameter vfile_1330, Parameter vaddr_1330, Parameter vlen_1331, Parameter vflags_1332, Parameter vvm_flags_1332, Parameter vpgoff_1333, Variable vmm_1336, Variable vinode_1409
where
not func_0(vfile_1330, vlen_1331, vpgoff_1333, vinode_1409)
and vfile_1330.getType().hasName("file *")
and func_1(vfile_1330)
and vlen_1331.getType().hasName("unsigned long")
and func_2(vlen_1331, vvm_flags_1332, vmm_1336)
and vvm_flags_1332.getType().hasName("vm_flags_t")
and vpgoff_1333.getType().hasName("unsigned long")
and func_3(vfile_1330, vaddr_1330, vlen_1331, vflags_1332, vpgoff_1333)
and vmm_1336.getType().hasName("mm_struct *")
and vinode_1409.getType().hasName("inode *")
and vfile_1330.getParentScope+() = func
and vaddr_1330.getParentScope+() = func
and vlen_1331.getParentScope+() = func
and vflags_1332.getParentScope+() = func
and vvm_flags_1332.getParentScope+() = func
and vpgoff_1333.getParentScope+() = func
and vmm_1336.getParentScope+() = func
and vinode_1409.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
