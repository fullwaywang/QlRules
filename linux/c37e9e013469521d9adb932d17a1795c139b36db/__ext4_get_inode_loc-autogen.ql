/**
 * @name linux-c37e9e013469521d9adb932d17a1795c139b36db-__ext4_get_inode_loc
 * @id cpp/linux/c37e9e013469521d9adb932d17a1795c139b36db/__ext4_get_inode_loc
 * @description linux-c37e9e013469521d9adb932d17a1795c139b36db-__ext4_get_inode_loc CVE-2018-10882
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_4499, Variable vsb_4504) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerFieldAccess
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="i_ino"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_4499
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="s_inodes_count"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s_es"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("EXT4_SB")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_4504
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-117"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="117")
}

predicate func_1(Parameter vinode_4499) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="i_ino"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinode_4499
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall)
}

predicate func_3(Variable vsb_4504) {
	exists(NotExpr target_3 |
		target_3.getOperand().(FunctionCall).getTarget().hasName("ext4_valid_inum")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_4504
		and target_3.getOperand().(FunctionCall).getArgument(1) instanceof PointerFieldAccess
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-117"
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="117")
}

predicate func_4(Parameter vinode_4499) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="i_sb"
		and target_4.getQualifier().(VariableAccess).getTarget()=vinode_4499)
}

from Function func, Parameter vinode_4499, Variable vsb_4504
where
not func_0(vinode_4499, vsb_4504)
and func_1(vinode_4499)
and func_3(vsb_4504)
and vinode_4499.getType().hasName("inode *")
and func_4(vinode_4499)
and vsb_4504.getType().hasName("super_block *")
and vinode_4499.getParentScope+() = func
and vsb_4504.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
