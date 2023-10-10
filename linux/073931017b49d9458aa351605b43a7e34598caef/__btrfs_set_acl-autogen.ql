/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-__btrfs_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/--btrfs-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-__btrfs_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_72, Parameter vacl_72) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_72
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_72)
}

predicate func_2(Parameter vinode_72, Parameter vacl_72) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_72
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_72
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_72)
}

predicate func_3(Variable vret_74) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vret_74
		and target_3.getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_74)
}

predicate func_6(Parameter vacl_72, Variable vret_74) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_74
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vacl_72
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_72)
}

from Function func, Parameter vinode_72, Parameter vacl_72, Variable vret_74
where
func_0(vinode_72, vacl_72)
and not func_2(vinode_72, vacl_72)
and func_3(vret_74)
and func_6(vacl_72, vret_74)
and vinode_72.getType().hasName("inode *")
and vacl_72.getType().hasName("posix_acl *")
and vret_74.getType().hasName("int")
and vinode_72.getParentScope+() = func
and vacl_72.getParentScope+() = func
and vret_74.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
