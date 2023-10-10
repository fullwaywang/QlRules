/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-__ext4_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/--ext4-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-__ext4_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_184, Parameter vacl_185) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_185
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_184)
}

predicate func_2(Parameter vinode_184, Parameter vacl_185) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_185
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_184
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_184)
}

predicate func_3(Parameter vinode_184) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="i_ctime"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_184
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ext4_current_time")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_184
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_4(Parameter vhandle_184, Parameter vinode_184) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("ext4_mark_inode_dirty")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhandle_184
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinode_184
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_8(Parameter vacl_185, Variable verror_190) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verror_190
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vacl_185
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verror_190
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Parameter vhandle_184, Parameter vinode_184, Parameter vacl_185, Variable verror_190
where
func_0(vinode_184, vacl_185)
and not func_2(vinode_184, vacl_185)
and func_3(vinode_184)
and func_4(vhandle_184, vinode_184)
and func_8(vacl_185, verror_190)
and vhandle_184.getType().hasName("handle_t *")
and vinode_184.getType().hasName("inode *")
and vacl_185.getType().hasName("posix_acl *")
and verror_190.getType().hasName("int")
and vhandle_184.getParentScope+() = func
and vinode_184.getParentScope+() = func
and vacl_185.getParentScope+() = func
and verror_190.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
