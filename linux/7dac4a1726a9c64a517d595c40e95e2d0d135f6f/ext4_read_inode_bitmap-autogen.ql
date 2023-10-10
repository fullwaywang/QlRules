/**
 * @name linux-7dac4a1726a9c64a517d595c40e95e2d0d135f6f-ext4_read_inode_bitmap
 * @id cpp/linux/7dac4a1726a9c64a517d595c40e95e2d0d135f6f/ext4-read-inode-bitmap
 * @description linux-7dac4a1726a9c64a517d595c40e95e2d0d135f6f-ext4_read_inode_bitmap CVE-2018-1093
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsb_122, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("EXT4_SB")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_122
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_1(Parameter vsb_122, Parameter vblock_group_122, Variable vbitmap_blk_126, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbitmap_blk_126
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="s_first_data_block"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s_es"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ext4_sb_info *")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbitmap_blk_126
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ext4_blocks_count")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="s_es"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ext4_sb_info *")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_122
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char[23]")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid inode bitmap blk %llu in block_group %u"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbitmap_blk_126
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vblock_group_122
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_PTR")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getOperand().(Literal).getValue()="117"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_4(Parameter vsb_122, Variable vdesc_124) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ext4_inode_bitmap")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vsb_122
		and target_4.getArgument(1).(VariableAccess).getTarget()=vdesc_124)
}

predicate func_5(Parameter vsb_122, Parameter vblock_group_122) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ext4_get_group_desc")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vsb_122
		and target_5.getArgument(1).(VariableAccess).getTarget()=vblock_group_122
		and target_5.getArgument(2).(Literal).getValue()="0")
}

predicate func_6(Parameter vsb_122, Variable vdesc_124, Variable vbitmap_blk_126) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=vbitmap_blk_126
		and target_6.getRValue().(FunctionCall).getTarget().hasName("ext4_inode_bitmap")
		and target_6.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_122
		and target_6.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdesc_124)
}

from Function func, Parameter vsb_122, Parameter vblock_group_122, Variable vdesc_124, Variable vbitmap_blk_126
where
not func_0(vsb_122, func)
and not func_1(vsb_122, vblock_group_122, vbitmap_blk_126, func)
and vsb_122.getType().hasName("super_block *")
and func_4(vsb_122, vdesc_124)
and vblock_group_122.getType().hasName("ext4_group_t")
and func_5(vsb_122, vblock_group_122)
and vdesc_124.getType().hasName("ext4_group_desc *")
and vbitmap_blk_126.getType().hasName("ext4_fsblk_t")
and func_6(vsb_122, vdesc_124, vbitmap_blk_126)
and vsb_122.getParentScope+() = func
and vblock_group_122.getParentScope+() = func
and vdesc_124.getParentScope+() = func
and vbitmap_blk_126.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
