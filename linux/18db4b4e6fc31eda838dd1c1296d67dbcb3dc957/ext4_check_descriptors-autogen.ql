/**
 * @name linux-18db4b4e6fc31eda838dd1c1296d67dbcb3dc957-ext4_check_descriptors
 * @id cpp/linux/18db4b4e6fc31eda838dd1c1296d67dbcb3dc957/ext4-check-descriptors
 * @description linux-18db4b4e6fc31eda838dd1c1296d67dbcb3dc957-ext4_check_descriptors 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vsb_2302) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_3(Variable vi_2313, Parameter vsb_2302) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof EqualityOperation
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode table for group %u overlaps superblock"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2313
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_5(Variable vinode_bitmap_2310, Variable vi_2313, Parameter vsb_2302, Parameter vsb_block_2303) {
	exists(EqualityOperation target_5 |
		target_5.getAnOperand().(VariableAccess).getTarget()=vinode_bitmap_2310
		and target_5.getAnOperand().(VariableAccess).getTarget()=vsb_block_2303
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode bitmap for group %u overlaps superblock"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2313)
}

predicate func_6(Variable vinode_table_2311, Variable vi_2313, Parameter vsb_2302, Parameter vsb_block_2303) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vinode_table_2311
		and target_6.getAnOperand().(VariableAccess).getTarget()=vsb_block_2303
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode table for group %u overlaps superblock"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2313)
}

predicate func_7(Variable vgdp_2321, Parameter vsb_2302) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("ext4_inode_bitmap")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_7.getArgument(1).(VariableAccess).getTarget()=vgdp_2321)
}

predicate func_8(Variable vi_2313, Parameter vsb_2302) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("__ext4_msg")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_8.getArgument(1).(StringLiteral).getValue()="3"
		and target_8.getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode bitmap for group %u overlaps superblock"
		and target_8.getArgument(3).(VariableAccess).getTarget()=vi_2313)
}

predicate func_9(Variable vi_2313, Parameter vsb_2302) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("__ext4_msg")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vsb_2302
		and target_9.getArgument(1).(StringLiteral).getValue()="3"
		and target_9.getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode table for group %u overlaps superblock"
		and target_9.getArgument(3).(VariableAccess).getTarget()=vi_2313)
}

from Function func, Variable vinode_bitmap_2310, Variable vinode_table_2311, Variable vi_2313, Variable vgdp_2321, Parameter vsb_2302, Parameter vsb_block_2303
where
not func_2(vsb_2302)
and not func_3(vi_2313, vsb_2302)
and func_5(vinode_bitmap_2310, vi_2313, vsb_2302, vsb_block_2303)
and func_6(vinode_table_2311, vi_2313, vsb_2302, vsb_block_2303)
and vinode_bitmap_2310.getType().hasName("ext4_fsblk_t")
and vinode_table_2311.getType().hasName("ext4_fsblk_t")
and vi_2313.getType().hasName("ext4_group_t")
and vsb_2302.getType().hasName("super_block *")
and func_7(vgdp_2321, vsb_2302)
and func_8(vi_2313, vsb_2302)
and func_9(vi_2313, vsb_2302)
and vsb_block_2303.getType().hasName("ext4_fsblk_t")
and vinode_bitmap_2310.getParentScope+() = func
and vinode_table_2311.getParentScope+() = func
and vi_2313.getParentScope+() = func
and vgdp_2321.getParentScope+() = func
and vsb_2302.getParentScope+() = func
and vsb_block_2303.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
