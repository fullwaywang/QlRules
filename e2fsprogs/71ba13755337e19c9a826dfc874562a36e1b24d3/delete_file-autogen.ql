/**
 * @name e2fsprogs-71ba13755337e19c9a826dfc874562a36e1b24d3-delete_file
 * @id cpp/e2fsprogs/71ba13755337e19c9a826dfc874562a36e1b24d3/delete-file
 * @description e2fsprogs-71ba13755337e19c9a826dfc874562a36e1b24d3-e2fsck/pass1b.c-delete_file CVE-2019-5188
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_684, Parameter vino_684, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="inode_reg_map"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_684
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ext2fs_unmark_inode_bitmap2")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="inode_reg_map"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_684
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vino_684
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctx_684, Parameter vino_684, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ext2fs_unmark_inode_bitmap2")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="inode_dir_map"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_684
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vino_684
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vctx_684, Parameter vino_684, ExprStmt target_4, ExprStmt target_5, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("ext2fs_unmark_inode_bitmap2")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="inode_used_map"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_684
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vino_684
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2)
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vctx_684, Parameter vino_684, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("ext2fs_unmark_inode_bitmap2")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="inode_bad_map"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_684
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vino_684
}

predicate func_4(Parameter vctx_684, Parameter vino_684, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("quota_data_sub")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="qctx"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_684
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="inode"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vino_684
		and target_4.getExpr().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="dup_blocks"
		and target_4.getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="blocksize"
}

predicate func_5(Parameter vino_684, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("ext2fs_inode_alloc_stats2")
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vino_684
		and target_5.getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_5.getExpr().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="i_mode"
		and target_5.getExpr().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inode"
		and target_5.getExpr().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_5.getExpr().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(Literal).getValue()="16384"
}

from Function func, Parameter vctx_684, Parameter vino_684, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vctx_684, vino_684, target_3, func)
and not func_1(vctx_684, vino_684, func)
and not func_2(vctx_684, vino_684, target_4, target_5, func)
and func_3(vctx_684, vino_684, target_3)
and func_4(vctx_684, vino_684, target_4)
and func_5(vino_684, target_5)
and vctx_684.getType().hasName("e2fsck_t")
and vino_684.getType().hasName("ext2_ino_t")
and vctx_684.getParentScope+() = func
and vino_684.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
