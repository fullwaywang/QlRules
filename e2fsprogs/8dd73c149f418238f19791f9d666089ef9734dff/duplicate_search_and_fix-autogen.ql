/**
 * @name e2fsprogs-8dd73c149f418238f19791f9d666089ef9734dff-duplicate_search_and_fix
 * @id cpp/e2fsprogs/8dd73c149f418238f19791f9d666089ef9734dff/duplicate-search-and-fix
 * @description e2fsprogs-8dd73c149f418238f19791f9d666089ef9734dff-e2fsck/rehash.c-duplicate_search_and_fix CVE-2019-5188
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_len_374, Parameter vfs_365, ExprStmt target_1, ExprStmt target_2, LogicalAndExpr target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_len_374
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ext2fs_unmark_valid")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfs_365
		and target_0.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnew_len_374, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_len_374
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ext2fs_dirent_name_len")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dir"
}

predicate func_2(Variable vnew_len_374, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dir"
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_len_374
}

predicate func_3(Parameter vfs_365, LogicalAndExpr target_3) {
		target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="s_flags"
		and target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="super"
		and target_3.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfs_365
		and target_3.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_4(Variable vnew_len_374, Parameter vfs_365, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ext2fs_dirhash2")
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_len_374
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="encoding"
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfs_365
		and target_4.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="s_hash_seed"
		and target_4.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="super"
		and target_4.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfs_365
		and target_4.getExpr().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hash"
		and target_4.getExpr().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="minor_hash"
}

from Function func, Variable vnew_len_374, Parameter vfs_365, ExprStmt target_1, ExprStmt target_2, LogicalAndExpr target_3, ExprStmt target_4
where
not func_0(vnew_len_374, vfs_365, target_1, target_2, target_3, target_4)
and func_1(vnew_len_374, target_1)
and func_2(vnew_len_374, target_2)
and func_3(vfs_365, target_3)
and func_4(vnew_len_374, vfs_365, target_4)
and vnew_len_374.getType().hasName("unsigned int")
and vfs_365.getType().hasName("ext2_filsys")
and vnew_len_374.getParentScope+() = func
and vfs_365.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
