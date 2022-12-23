/**
 * @name linux-0fa3ecd87848c9c93c2c828ef4c3a8ca36ce46c7-inode_init_owner
 * @id cpp/linux/0fa3ecd87848c9c93c2c828ef4c3a8ca36ce46c7/inode_init_owner
 * @description linux-0fa3ecd87848c9c93c2c828ef4c3a8ca36ce46c7-inode_init_owner 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_1996, Parameter vdir_1996, Parameter vmode_1997) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmode_1997
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("in_group_p")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="i_gid"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_1996
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("capable_wrt_inode_uidgid")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdir_1996
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(VariableAccess).getTarget()=vmode_1997
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="-1025"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(Literal).getValue()="1024"
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmode_1997
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="16384")
}

predicate func_1(Parameter vinode_1996) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="i_gid"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinode_1996)
}

predicate func_2(Parameter vdir_1996) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="i_gid"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdir_1996)
}

predicate func_3(Parameter vmode_1997) {
	exists(AssignOrExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vmode_1997
		and target_3.getRValue().(Literal).getValue()="1024")
}

predicate func_4(Parameter vinode_1996, Parameter vmode_1997) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_4.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_1996
		and target_4.getRValue().(VariableAccess).getTarget()=vmode_1997)
}

from Function func, Parameter vinode_1996, Parameter vdir_1996, Parameter vmode_1997
where
not func_0(vinode_1996, vdir_1996, vmode_1997)
and vinode_1996.getType().hasName("inode *")
and func_1(vinode_1996)
and vdir_1996.getType().hasName("const inode *")
and func_2(vdir_1996)
and vmode_1997.getType().hasName("umode_t")
and func_3(vmode_1997)
and func_4(vinode_1996, vmode_1997)
and vinode_1996.getParentScope+() = func
and vdir_1996.getParentScope+() = func
and vmode_1997.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
