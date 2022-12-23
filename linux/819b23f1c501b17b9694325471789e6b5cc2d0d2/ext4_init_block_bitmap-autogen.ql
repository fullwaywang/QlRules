/**
 * @name linux-819b23f1c501b17b9694325471789e6b5cc2d0d2-ext4_init_block_bitmap
 * @id cpp/linux/819b23f1c501b17b9694325471789e6b5cc2d0d2/ext4_init_block_bitmap
 * @description linux-819b23f1c501b17b9694325471789e6b5cc2d0d2-ext4_init_block_bitmap 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsb_179, Parameter vblock_group_181, Variable vtmp_186) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ext4_block_in_group")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vsb_179
		and target_0.getArgument(1).(VariableAccess).getTarget()=vtmp_186
		and target_0.getArgument(2).(VariableAccess).getTarget()=vblock_group_181)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_5(Parameter vsb_179, Variable vflex_bg_187) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vflex_bg_187
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ext4_has_feature_flex_bg")
		and target_5.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_179)
}

predicate func_6(Parameter vbh_180, Variable vsbi_185, Variable vstart_186, Variable vtmp_186, Variable vflex_bg_187) {
	exists(LogicalOrExpr target_6 |
		target_6.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vflex_bg_187
		and target_6.getAnOperand() instanceof FunctionCall
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__set_bit_le")
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vtmp_186
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstart_186
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="s_cluster_bits"
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_185
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="b_data"
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbh_180)
}

predicate func_7(Parameter vbh_180, Variable vsbi_185, Variable vstart_186, Variable vtmp_186, Variable vflex_bg_187, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vflex_bg_187
		and target_7.getCondition().(LogicalOrExpr).getAnOperand() instanceof FunctionCall
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__set_bit_le")
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vtmp_186
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstart_186
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="s_cluster_bits"
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_185
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="b_data"
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbh_180
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

from Function func, Parameter vsb_179, Parameter vbh_180, Parameter vblock_group_181, Variable vsbi_185, Variable vstart_186, Variable vtmp_186, Variable vflex_bg_187
where
func_0(vsb_179, vblock_group_181, vtmp_186)
and func_3(func)
and func_5(vsb_179, vflex_bg_187)
and func_6(vbh_180, vsbi_185, vstart_186, vtmp_186, vflex_bg_187)
and func_7(vbh_180, vsbi_185, vstart_186, vtmp_186, vflex_bg_187, func)
and vsb_179.getType().hasName("super_block *")
and vbh_180.getType().hasName("buffer_head *")
and vblock_group_181.getType().hasName("ext4_group_t")
and vsbi_185.getType().hasName("ext4_sb_info *")
and vstart_186.getType().hasName("ext4_fsblk_t")
and vtmp_186.getType().hasName("ext4_fsblk_t")
and vflex_bg_187.getType().hasName("int")
and vsb_179.getParentScope+() = func
and vbh_180.getParentScope+() = func
and vblock_group_181.getParentScope+() = func
and vsbi_185.getParentScope+() = func
and vstart_186.getParentScope+() = func
and vtmp_186.getParentScope+() = func
and vflex_bg_187.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
