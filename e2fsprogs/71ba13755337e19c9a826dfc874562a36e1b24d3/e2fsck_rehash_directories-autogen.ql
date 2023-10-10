/**
 * @name e2fsprogs-71ba13755337e19c9a826dfc874562a36e1b24d3-e2fsck_rehash_directories
 * @id cpp/e2fsprogs/71ba13755337e19c9a826dfc874562a36e1b24d3/e2fsck-rehash-directories
 * @description e2fsprogs-71ba13755337e19c9a826dfc874562a36e1b24d3-e2fsck/rehash.c-e2fsck_rehash_directories CVE-2019-5188
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_984, Variable vino_993, EqualityOperation target_3, ExprStmt target_4, AddressOfExpr target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ext2fs_test_inode_bitmap2")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="inode_dir_map"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_984
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vino_993
		and target_0.getThen().(ContinueStmt).toString() = "continue;"
		and target_3.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Function func, LabelStmt target_2) {
		target_2.toString() = "label ...:"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vctx_984, EqualityOperation target_3) {
		target_3.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("e2fsck_dir_info_iter")
		and target_3.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_984
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vctx_984, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("fix_problem")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_984
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="200704"
}

predicate func_5(Variable vino_993, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vino_993
}

predicate func_6(Variable vino_993, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="dir"
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vino_993
}

from Function func, Parameter vctx_984, Variable vino_993, LabelStmt target_2, EqualityOperation target_3, ExprStmt target_4, AddressOfExpr target_5, ExprStmt target_6
where
not func_0(vctx_984, vino_993, target_3, target_4, target_5, target_6)
and func_2(func, target_2)
and func_3(vctx_984, target_3)
and func_4(vctx_984, target_4)
and func_5(vino_993, target_5)
and func_6(vino_993, target_6)
and vctx_984.getType().hasName("e2fsck_t")
and vino_993.getType().hasName("ext2_ino_t")
and vctx_984.getParentScope+() = func
and vino_993.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
