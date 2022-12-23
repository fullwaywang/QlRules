/**
 * @name linux-8cdb5240ec5928b20490a2bb34cb87e9a5f40226-ext4_xattr_make_inode_space
 * @id cpp/linux/8cdb5240ec5928b20490a2bb34cb87e9a5f40226/ext4_xattr_make_inode_space
 * @description linux-8cdb5240ec5928b20490a2bb34cb87e9a5f40226-ext4_xattr_make_inode_space CVE-2018-10880
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vlast_2647) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="e_name_len"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlast_2647
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="e_name_index"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlast_2647
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="7"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="e_name"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlast_2647
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="data"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_0.getThen().(ContinueStmt).toString() = "continue;")
}

predicate func_1(Function func) {
	exists(LabelStmt target_1 |
		target_1.toString() = "label ...:"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vlast_2647) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="e_name_len"
		and target_2.getQualifier().(VariableAccess).getTarget()=vlast_2647)
}

from Function func, Variable vlast_2647
where
not func_0(vlast_2647)
and not func_1(func)
and vlast_2647.getType().hasName("ext4_xattr_entry *")
and func_2(vlast_2647)
and vlast_2647.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
