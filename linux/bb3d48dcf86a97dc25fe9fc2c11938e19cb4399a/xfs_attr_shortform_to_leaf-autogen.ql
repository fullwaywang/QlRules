/**
 * @name linux-bb3d48dcf86a97dc25fe9fc2c11938e19cb4399a-xfs_attr_shortform_to_leaf
 * @id cpp/linux/bb3d48dcf86a97dc25fe9fc2c11938e19cb4399a/xfs_attr_shortform_to_leaf
 * @description linux-bb3d48dcf86a97dc25fe9fc2c11938e19cb4399a-xfs_attr_shortform_to_leaf 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable verror_758, Variable vbp_760) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vbp_760
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verror_758)
}

predicate func_1(Variable vbp_760, Parameter vargs_750) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("xfs_da_shrink_inode")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vargs_750
		and target_1.getArgument(1).(Literal).getValue()="0"
		and target_1.getArgument(2).(VariableAccess).getTarget()=vbp_760)
}

predicate func_2(Variable verror_758) {
	exists(IfStmt target_2 |
		target_2.getCondition().(VariableAccess).getTarget()=verror_758
		and target_2.getThen().(GotoStmt).toString() = "goto ..."
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verror_758)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable verror_758) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_758
		and target_4.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verror_758)
}

predicate func_5(Variable verror_758, Variable vbp_760) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbp_760
		and target_5.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verror_758)
}

predicate func_6(Variable vblkno_759, Variable vbp_760, Parameter vargs_750) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vbp_760
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xfs_attr3_leaf_create")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vargs_750
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vblkno_759)
}

from Function func, Variable verror_758, Variable vblkno_759, Variable vbp_760, Parameter vargs_750
where
not func_0(verror_758, vbp_760)
and func_1(vbp_760, vargs_750)
and func_2(verror_758)
and func_3(func)
and func_4(verror_758)
and func_5(verror_758, vbp_760)
and verror_758.getType().hasName("int")
and vbp_760.getType().hasName("xfs_buf *")
and func_6(vblkno_759, vbp_760, vargs_750)
and vargs_750.getType().hasName("xfs_da_args *")
and verror_758.getParentScope+() = func
and vblkno_759.getParentScope+() = func
and vbp_760.getParentScope+() = func
and vargs_750.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
