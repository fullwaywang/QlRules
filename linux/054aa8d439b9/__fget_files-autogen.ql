/**
 * @name linux-054aa8d439b9-__fget_files
 * @id cpp/linux/054aa8d439b9/--fget-files
 * @description linux-054aa8d439b9-__fget_files 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfile_847, Parameter vfd_844, Parameter vmask_845, Parameter vrefs_845, Parameter vfiles_844) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("files_lookup_fd_raw")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfiles_844
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfd_844
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vfile_847
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fput_many")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfile_847
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrefs_845
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="f_mode"
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_847
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getTarget()=vmask_845)
}

predicate func_3(Variable vfile_847) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="f_count"
		and target_3.getQualifier().(VariableAccess).getTarget()=vfile_847)
}

predicate func_4(Parameter vfd_844, Parameter vfiles_844) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("files_lookup_fd_rcu")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vfiles_844
		and target_4.getArgument(1).(VariableAccess).getTarget()=vfd_844)
}

predicate func_5(Variable vfile_847, Parameter vrefs_845) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("atomic_long_add_unless")
		and target_5.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="f_count"
		and target_5.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_847
		and target_5.getArgument(1).(VariableAccess).getTarget()=vrefs_845
		and target_5.getArgument(2).(Literal).getValue()="0")
}

from Function func, Variable vfile_847, Parameter vfd_844, Parameter vmask_845, Parameter vrefs_845, Parameter vfiles_844
where
not func_0(vfile_847, vfd_844, vmask_845, vrefs_845, vfiles_844)
and vfile_847.getType().hasName("file *")
and func_3(vfile_847)
and vfd_844.getType().hasName("unsigned int")
and func_4(vfd_844, vfiles_844)
and vmask_845.getType().hasName("fmode_t")
and vrefs_845.getType().hasName("unsigned int")
and func_5(vfile_847, vrefs_845)
and vfiles_844.getType().hasName("files_struct *")
and vfile_847.getParentScope+() = func
and vfd_844.getParentScope+() = func
and vmask_845.getParentScope+() = func
and vrefs_845.getParentScope+() = func
and vfiles_844.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
