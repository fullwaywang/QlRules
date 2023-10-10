/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-__jfs_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/--jfs-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-__jfs_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_69, Parameter vacl_70) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_70
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_69)
}

predicate func_2(Parameter vinode_69, Parameter vacl_70) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_70
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_69
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_69)
}

predicate func_3(Variable vrc_73) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vrc_73
		and target_3.getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vrc_73)
}

predicate func_6(Parameter vacl_70, Variable vrc_73) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_73
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vacl_70
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_70)
}

from Function func, Parameter vinode_69, Parameter vacl_70, Variable vrc_73
where
func_0(vinode_69, vacl_70)
and not func_2(vinode_69, vacl_70)
and func_3(vrc_73)
and func_6(vacl_70, vrc_73)
and vinode_69.getType().hasName("inode *")
and vacl_70.getType().hasName("posix_acl *")
and vrc_73.getType().hasName("int")
and vinode_69.getParentScope+() = func
and vacl_70.getParentScope+() = func
and vrc_73.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
