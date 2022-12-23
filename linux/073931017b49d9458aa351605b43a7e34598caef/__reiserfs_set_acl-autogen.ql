/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-__reiserfs_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/--reiserfs-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-__reiserfs_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_233, Parameter vacl_234) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_234
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_233)
}

predicate func_2(Parameter vinode_233, Parameter vacl_234) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_234
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_233
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_233)
}

predicate func_6(Parameter vacl_234, Variable verror_239) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verror_239
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vacl_234
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verror_239
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Parameter vinode_233, Parameter vacl_234, Variable verror_239
where
func_0(vinode_233, vacl_234)
and not func_2(vinode_233, vacl_234)
and func_6(vacl_234, verror_239)
and vinode_233.getType().hasName("inode *")
and vacl_234.getType().hasName("posix_acl *")
and verror_239.getType().hasName("int")
and vinode_233.getParentScope+() = func
and vacl_234.getParentScope+() = func
and verror_239.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
