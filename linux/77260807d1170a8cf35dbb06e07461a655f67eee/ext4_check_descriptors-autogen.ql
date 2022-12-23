/**
 * @name linux-77260807d1170a8cf35dbb06e07461a655f67eee-ext4_check_descriptors
 * @id cpp/linux/77260807d1170a8cf35dbb06e07461a655f67eee/ext4_check_descriptors
 * @description linux-77260807d1170a8cf35dbb06e07461a655f67eee-ext4_check_descriptors 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsb_2344, Parameter vsb_block_2345, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsb_block_2345
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("ext4_bg_num_gdb")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_0)
}

predicate func_1(Parameter vsb_2344, Parameter vsb_block_2345, Variable vblock_bitmap_2351, Variable vi_2355) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vblock_bitmap_2351
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsb_block_2345
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vblock_bitmap_2351
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ext4_fsblk_t")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Block bitmap for group %u overlaps block group descriptors"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2355
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_4(Parameter vsb_2344, Parameter vsb_block_2345, Variable vinode_bitmap_2352, Variable vi_2355) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vinode_bitmap_2352
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsb_block_2345
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vinode_bitmap_2352
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ext4_fsblk_t")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode bitmap for group %u overlaps block group descriptors"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2355
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_7(Parameter vsb_2344, Parameter vsb_block_2345, Variable vinode_table_2353, Variable vi_2355) {
	exists(IfStmt target_7 |
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vinode_table_2353
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsb_block_2345
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vinode_table_2353
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ext4_fsblk_t")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode table for group %u overlaps block group descriptors"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2355
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_10(Parameter vsb_2344) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("EXT4_SB")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vsb_2344)
}

predicate func_11(Parameter vsb_2344) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("sb_rdonly")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vsb_2344)
}

predicate func_14(Parameter vsb_2344, Parameter vsb_block_2345, Variable vblock_bitmap_2351, Variable vi_2355) {
	exists(EqualityOperation target_14 |
		target_14.getAnOperand().(VariableAccess).getTarget()=vblock_bitmap_2351
		and target_14.getAnOperand().(VariableAccess).getTarget()=vsb_block_2345
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Block bitmap for group %u overlaps superblock"
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2355
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_15(Parameter vsb_2344, Parameter vsb_block_2345, Variable vinode_bitmap_2352, Variable vi_2355) {
	exists(EqualityOperation target_15 |
		target_15.getAnOperand().(VariableAccess).getTarget()=vinode_bitmap_2352
		and target_15.getAnOperand().(VariableAccess).getTarget()=vsb_block_2345
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode bitmap for group %u overlaps superblock"
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2355
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_15.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_16(Parameter vsb_2344, Parameter vsb_block_2345, Variable vinode_table_2353, Variable vi_2355) {
	exists(EqualityOperation target_16 |
		target_16.getAnOperand().(VariableAccess).getTarget()=vinode_table_2353
		and target_16.getAnOperand().(VariableAccess).getTarget()=vsb_block_2345
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode table for group %u overlaps superblock"
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vi_2355
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sb_rdonly")
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_16.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_20(Parameter vsb_2344, Variable vi_2355) {
	exists(FunctionCall target_20 |
		target_20.getTarget().hasName("__ext4_msg")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_20.getArgument(1).(StringLiteral).getValue()="3"
		and target_20.getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Block bitmap for group %u overlaps superblock"
		and target_20.getArgument(3).(VariableAccess).getTarget()=vi_2355)
}

predicate func_21(Parameter vsb_2344, Variable vi_2355) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("__ext4_msg")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_21.getArgument(1).(StringLiteral).getValue()="3"
		and target_21.getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode bitmap for group %u overlaps superblock"
		and target_21.getArgument(3).(VariableAccess).getTarget()=vi_2355)
}

predicate func_22(Parameter vsb_2344, Variable vi_2355) {
	exists(FunctionCall target_22 |
		target_22.getTarget().hasName("__ext4_msg")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vsb_2344
		and target_22.getArgument(1).(StringLiteral).getValue()="3"
		and target_22.getArgument(2).(StringLiteral).getValue()="ext4_check_descriptors: Inode table for group %u overlaps superblock"
		and target_22.getArgument(3).(VariableAccess).getTarget()=vi_2355)
}

from Function func, Parameter vsb_2344, Parameter vsb_block_2345, Variable vblock_bitmap_2351, Variable vinode_bitmap_2352, Variable vinode_table_2353, Variable vi_2355
where
not func_0(vsb_2344, vsb_block_2345, func)
and not func_1(vsb_2344, vsb_block_2345, vblock_bitmap_2351, vi_2355)
and not func_4(vsb_2344, vsb_block_2345, vinode_bitmap_2352, vi_2355)
and not func_7(vsb_2344, vsb_block_2345, vinode_table_2353, vi_2355)
and vsb_2344.getType().hasName("super_block *")
and func_10(vsb_2344)
and func_11(vsb_2344)
and vsb_block_2345.getType().hasName("ext4_fsblk_t")
and func_14(vsb_2344, vsb_block_2345, vblock_bitmap_2351, vi_2355)
and func_15(vsb_2344, vsb_block_2345, vinode_bitmap_2352, vi_2355)
and func_16(vsb_2344, vsb_block_2345, vinode_table_2353, vi_2355)
and vblock_bitmap_2351.getType().hasName("ext4_fsblk_t")
and vinode_bitmap_2352.getType().hasName("ext4_fsblk_t")
and vinode_table_2353.getType().hasName("ext4_fsblk_t")
and vi_2355.getType().hasName("ext4_group_t")
and func_20(vsb_2344, vi_2355)
and func_21(vsb_2344, vi_2355)
and func_22(vsb_2344, vi_2355)
and vsb_2344.getParentScope+() = func
and vsb_block_2345.getParentScope+() = func
and vblock_bitmap_2351.getParentScope+() = func
and vinode_bitmap_2352.getParentScope+() = func
and vinode_table_2353.getParentScope+() = func
and vi_2355.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
