/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_init_debugfs
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-init-debugfs
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_init_debugfs CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="fw_debug"
		and not target_0.getValue()="fw_debug_wm"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vfops_fw_debug) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vfops_fw_debug)
}

predicate func_2(Variable vdev_450, Variable vdir_452, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("debugfs_create_file")
		and target_2.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="fw_debug_wa"
		and target_2.getExpr().(FunctionCall).getArgument(1).(OctalLiteral).getValue()="384"
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdir_452
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdev_450
		and target_2.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const file_operations")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_2))
}

predicate func_3(Variable vdev_450, Variable vdir_452, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("debugfs_create_file")
		and target_3.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="fw_util_wm"
		and target_3.getExpr().(FunctionCall).getArgument(1).(OctalLiteral).getValue()="256"
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdir_452
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdev_450
		and target_3.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const file_operations")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_3))
}

predicate func_4(Variable vdev_450, Variable vdir_452, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("debugfs_create_file")
		and target_4.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="fw_util_wa"
		and target_4.getExpr().(FunctionCall).getArgument(1).(OctalLiteral).getValue()="256"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdir_452
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdev_450
		and target_4.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("const file_operations")
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_4))
}

predicate func_5(Variable vdev_450, Variable vdir_452, Variable vfops_fw_debug) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("debugfs_create_file")
		and target_5.getArgument(0) instanceof StringLiteral
		and target_5.getArgument(1).(OctalLiteral).getValue()="384"
		and target_5.getArgument(2).(VariableAccess).getTarget()=vdir_452
		and target_5.getArgument(3).(VariableAccess).getTarget()=vdev_450
		and target_5.getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfops_fw_debug)
}

from Function func, Variable vdev_450, Variable vdir_452, Variable vfops_fw_debug
where
func_0(func)
and func_1(vfops_fw_debug)
and not func_2(vdev_450, vdir_452, func)
and not func_3(vdev_450, vdir_452, func)
and not func_4(vdev_450, vdir_452, func)
and vdev_450.getType().hasName("mt7915_dev *")
and func_5(vdev_450, vdir_452, vfops_fw_debug)
and vdir_452.getType().hasName("dentry *")
and vdev_450.getParentScope+() = func
and vdir_452.getParentScope+() = func
and not vfops_fw_debug.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
