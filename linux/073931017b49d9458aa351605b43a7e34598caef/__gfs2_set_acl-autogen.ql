/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-__gfs2_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/--gfs2-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-__gfs2_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vacl_82, Variable vmode_93) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_82
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_93)
}

predicate func_2(Parameter vinode_82, Parameter vacl_82) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_82
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_82
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand() instanceof PointerFieldAccess)
}

predicate func_3(Variable verror_84) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=verror_84
		and target_3.getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=verror_84)
}

predicate func_5(Parameter vinode_82, Variable vmode_93) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="i_mode"
		and target_5.getQualifier().(VariableAccess).getTarget()=vinode_82
		and target_5.getParent().(AssignExpr).getLValue() = target_5
		and target_5.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmode_93)
}

predicate func_6(Parameter vinode_82, Variable vmode_93) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("mark_inode_dirty")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_82
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmode_93
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_82)
}

predicate func_9(Variable vmode_93) {
	exists(VariableAccess target_9 |
		target_9.getTarget()=vmode_93)
}

predicate func_12(Parameter vtype_82, Variable vmode_93) {
	exists(IfStmt target_12 |
		target_12.getCondition() instanceof EqualityOperation
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmode_93
		and target_12.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_82
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="32768")
}

predicate func_14(Parameter vinode_82) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="i_mode"
		and target_14.getQualifier().(VariableAccess).getTarget()=vinode_82)
}

from Function func, Parameter vinode_82, Parameter vacl_82, Parameter vtype_82, Variable verror_84, Variable vmode_93
where
func_0(vacl_82, vmode_93)
and not func_2(vinode_82, vacl_82)
and func_3(verror_84)
and func_5(vinode_82, vmode_93)
and func_6(vinode_82, vmode_93)
and func_9(vmode_93)
and func_12(vtype_82, vmode_93)
and vinode_82.getType().hasName("inode *")
and func_14(vinode_82)
and vacl_82.getType().hasName("posix_acl *")
and vtype_82.getType().hasName("int")
and verror_84.getType().hasName("int")
and vmode_93.getType().hasName("umode_t")
and vinode_82.getParentScope+() = func
and vacl_82.getParentScope+() = func
and vtype_82.getParentScope+() = func
and verror_84.getParentScope+() = func
and vmode_93.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
