/**
 * @name linux-7dac4a1726a9c64a517d595c40e95e2d0d135f6f-ext4_read_block_bitmap_nowait
 * @id cpp/linux/7dac4a1726a9c64a517d595c40e95e2d0d135f6f/ext4-read-block-bitmap-nowait
 * @description linux-7dac4a1726a9c64a517d595c40e95e2d0d135f6f-ext4_read_block_bitmap_nowait CVE-2018-1093
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsb_417, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("EXT4_SB")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_417
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_1(Parameter vsb_417, Parameter vblock_group_417, Variable vbitmap_blk_421, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbitmap_blk_421
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="s_first_data_block"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s_es"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ext4_sb_info *")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbitmap_blk_421
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ext4_blocks_count")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="s_es"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ext4_sb_info *")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_417
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char[30]")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid block bitmap block %llu in block_group %u"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbitmap_blk_421
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vblock_group_417
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_PTR")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getOperand().(Literal).getValue()="117"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_4(Parameter vsb_417, Variable vdesc_419) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ext4_block_bitmap")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vsb_417
		and target_4.getArgument(1).(VariableAccess).getTarget()=vdesc_419)
}

predicate func_5(Parameter vsb_417, Parameter vblock_group_417) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ext4_get_group_desc")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vsb_417
		and target_5.getArgument(1).(VariableAccess).getTarget()=vblock_group_417
		and target_5.getArgument(2).(Literal).getValue()="0")
}

predicate func_6(Parameter vsb_417, Variable vdesc_419, Variable vbitmap_blk_421) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=vbitmap_blk_421
		and target_6.getRValue().(FunctionCall).getTarget().hasName("ext4_block_bitmap")
		and target_6.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_417
		and target_6.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdesc_419)
}

from Function func, Parameter vsb_417, Parameter vblock_group_417, Variable vdesc_419, Variable vbitmap_blk_421
where
not func_0(vsb_417, func)
and not func_1(vsb_417, vblock_group_417, vbitmap_blk_421, func)
and vsb_417.getType().hasName("super_block *")
and func_4(vsb_417, vdesc_419)
and vblock_group_417.getType().hasName("ext4_group_t")
and func_5(vsb_417, vblock_group_417)
and vdesc_419.getType().hasName("ext4_group_desc *")
and vbitmap_blk_421.getType().hasName("ext4_fsblk_t")
and func_6(vsb_417, vdesc_419, vbitmap_blk_421)
and vsb_417.getParentScope+() = func
and vblock_group_417.getParentScope+() = func
and vdesc_419.getParentScope+() = func
and vbitmap_blk_421.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
