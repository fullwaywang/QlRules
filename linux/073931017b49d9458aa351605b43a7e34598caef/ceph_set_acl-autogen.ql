/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-ceph_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/ceph-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-ceph_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vacl_86, Variable vnew_mode_92) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_86
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnew_mode_92)
}

predicate func_2(Parameter vinode_86, Parameter vacl_86, Variable vnew_mode_92) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_86
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_86
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnew_mode_92)
}

predicate func_4(Parameter vacl_86, Variable vret_88) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_88
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getThen().(GotoStmt).toString() = "goto ..."
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_86)
}

predicate func_9(Parameter vinode_86) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="i_mode"
		and target_9.getQualifier().(VariableAccess).getTarget()=vinode_86)
}

from Function func, Parameter vinode_86, Parameter vacl_86, Variable vret_88, Variable vnew_mode_92
where
func_0(vacl_86, vnew_mode_92)
and not func_2(vinode_86, vacl_86, vnew_mode_92)
and func_4(vacl_86, vret_88)
and vinode_86.getType().hasName("inode *")
and func_9(vinode_86)
and vacl_86.getType().hasName("posix_acl *")
and vret_88.getType().hasName("int")
and vnew_mode_92.getType().hasName("umode_t")
and vinode_86.getParentScope+() = func
and vacl_86.getParentScope+() = func
and vret_88.getParentScope+() = func
and vnew_mode_92.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
