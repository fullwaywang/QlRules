/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-hfsplus_set_posix_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/hfsplus-set-posix-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-hfsplus_set_posix_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vacl_54, Parameter vinode_54) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_54
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_54)
}

predicate func_2(Parameter vacl_54, Parameter vinode_54) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_54
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_54
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_54)
}

predicate func_4(Variable verr_57) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=verr_57
		and target_4.getGreaterOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=verr_57)
}

predicate func_5(Parameter vacl_54) {
	exists(ConditionalExpr target_5 |
		target_5.getCondition().(VariableAccess).getTarget()=vacl_54
		and target_5.getThen().(UnaryMinusExpr).getValue()="-13"
		and target_5.getThen().(UnaryMinusExpr).getOperand().(Literal).getValue()="13"
		and target_5.getElse().(Literal).getValue()="0")
}

predicate func_6(Variable verr_57) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=verr_57
		and target_6.getRValue() instanceof FunctionCall)
}

predicate func_7(Parameter vinode_54) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="i_ino"
		and target_7.getQualifier().(VariableAccess).getTarget()=vinode_54)
}

from Function func, Parameter vacl_54, Variable verr_57, Parameter vinode_54
where
func_0(vacl_54, vinode_54)
and not func_2(vacl_54, vinode_54)
and func_4(verr_57)
and vacl_54.getType().hasName("posix_acl *")
and func_5(vacl_54)
and verr_57.getType().hasName("int")
and func_6(verr_57)
and vinode_54.getType().hasName("inode *")
and func_7(vinode_54)
and vacl_54.getParentScope+() = func
and verr_57.getParentScope+() = func
and vinode_54.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
