/**
 * @name linux-7dac4a1726a9c64a517d595c40e95e2d0d135f6f-ext4_valid_block_bitmap
 * @id cpp/linux/7dac4a1726a9c64a517d595c40e95e2d0d135f6f/ext4-valid-block-bitmap
 * @description linux-7dac4a1726a9c64a517d595c40e95e2d0d135f6f-ext4_valid_block_bitmap CVE-2018-1093
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsb_316, Variable vsbi_321, Variable voffset_322, Variable vblk_324) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_322
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=voffset_322
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="s_cluster_bits"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_321
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="s_blocksize"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_316
		and target_0.getAnOperand() instanceof NotExpr
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vblk_324)
}

predicate func_2(Parameter vsb_316, Variable vsbi_321, Variable voffset_322, Variable vblk_324, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_322
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=voffset_322
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="s_cluster_bits"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_321
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="s_blocksize"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_316
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_322
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="s_itb_per_group"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_321
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="s_cluster_bits"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_321
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="s_blocksize"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_316
		and target_2.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vblk_324
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vbh_319, Variable vsbi_321, Variable voffset_322, Variable vblk_324) {
	exists(NotExpr target_3 |
		target_3.getOperand().(FunctionCall).getTarget().hasName("test_bit_le")
		and target_3.getOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=voffset_322
		and target_3.getOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="s_cluster_bits"
		and target_3.getOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_321
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="b_data"
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbh_319
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vblk_324)
}

predicate func_5(Parameter vsb_316, Parameter vdesc_317) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ext4_block_bitmap")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vsb_316
		and target_5.getArgument(1).(VariableAccess).getTarget()=vdesc_317)
}

predicate func_6(Parameter vsb_316, Parameter vdesc_317) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("ext4_inode_bitmap")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vsb_316
		and target_6.getArgument(1).(VariableAccess).getTarget()=vdesc_317)
}

predicate func_7(Parameter vsb_316, Parameter vdesc_317) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("ext4_inode_table")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vsb_316
		and target_7.getArgument(1).(VariableAccess).getTarget()=vdesc_317)
}

predicate func_8(Variable vsbi_321) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="s_cluster_bits"
		and target_8.getQualifier().(VariableAccess).getTarget()=vsbi_321)
}

predicate func_10(Variable voffset_322, Variable vblk_324, Variable vgroup_first_block_325) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=voffset_322
		and target_10.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vblk_324
		and target_10.getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vgroup_first_block_325)
}

predicate func_13(Variable voffset_322, Variable vblk_324, Variable vgroup_first_block_325) {
	exists(SubExpr target_13 |
		target_13.getLeftOperand().(VariableAccess).getTarget()=vblk_324
		and target_13.getRightOperand().(VariableAccess).getTarget()=vgroup_first_block_325
		and target_13.getParent().(AssignExpr).getRValue() = target_13
		and target_13.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_322)
}

from Function func, Parameter vsb_316, Parameter vdesc_317, Parameter vbh_319, Variable vsbi_321, Variable voffset_322, Variable vblk_324, Variable vgroup_first_block_325
where
not func_0(vsb_316, vsbi_321, voffset_322, vblk_324)
and not func_2(vsb_316, vsbi_321, voffset_322, vblk_324, func)
and func_3(vbh_319, vsbi_321, voffset_322, vblk_324)
and vsb_316.getType().hasName("super_block *")
and func_5(vsb_316, vdesc_317)
and func_6(vsb_316, vdesc_317)
and func_7(vsb_316, vdesc_317)
and vdesc_317.getType().hasName("ext4_group_desc *")
and vbh_319.getType().hasName("buffer_head *")
and vsbi_321.getType().hasName("ext4_sb_info *")
and func_8(vsbi_321)
and voffset_322.getType().hasName("ext4_grpblk_t")
and func_10(voffset_322, vblk_324, vgroup_first_block_325)
and vblk_324.getType().hasName("ext4_fsblk_t")
and func_13(voffset_322, vblk_324, vgroup_first_block_325)
and vgroup_first_block_325.getType().hasName("ext4_fsblk_t")
and vsb_316.getParentScope+() = func
and vdesc_317.getParentScope+() = func
and vbh_319.getParentScope+() = func
and vsbi_321.getParentScope+() = func
and voffset_322.getParentScope+() = func
and vblk_324.getParentScope+() = func
and vgroup_first_block_325.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
