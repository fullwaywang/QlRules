/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-xfs_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/xfs-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-xfs_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vacl_248, Variable vmode_260) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_248
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_260)
}

predicate func_1(Parameter vinode_248, Parameter vacl_248, Variable vmode_260) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vacl_248
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_248
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_260)
}

predicate func_7(Parameter vinode_248) {
	exists(Initializer target_7 |
		target_7.getExpr().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_7.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_248)
}

from Function func, Parameter vinode_248, Parameter vacl_248, Variable verror_250, Variable vmode_260
where
func_0(vacl_248, vmode_260)
and not func_1(vinode_248, vacl_248, vmode_260)
and func_7(vinode_248)
and vinode_248.getType().hasName("inode *")
and vacl_248.getType().hasName("posix_acl *")
and verror_250.getType().hasName("int")
and vmode_260.getType().hasName("umode_t")
and vinode_248.getParentScope+() = func
and vacl_248.getParentScope+() = func
and verror_250.getParentScope+() = func
and vmode_260.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
