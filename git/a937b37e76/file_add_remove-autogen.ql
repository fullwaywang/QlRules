/**
 * @name git-a937b37e76-file_add_remove
 * @id cpp/git/a937b37e76/file-add-remove
 * @description git-a937b37e76-revision.c-file_add_remove CVE-2017-15298
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="3"
		and not target_0.getValue()="1"
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vtree_difference, ExprStmt target_4, ExprStmt target_5) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="remove_empty_trees"
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("rev_info *")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtree_difference
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtree_difference, ExprStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vtree_difference
		and target_2.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vtree_difference, ExprStmt target_4, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vtree_difference
		and target_3.getAnOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(ExprStmt target_4) {
		target_4.getExpr().(CommaExpr).getLeftOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="1024"
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="touched_flags"
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="1024"
}

predicate func_5(Variable vtree_difference, ExprStmt target_5) {
		target_5.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vtree_difference
}

from Function func, Variable vtree_difference, Literal target_0, VariableAccess target_2, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5
where
func_0(func, target_0)
and not func_1(vtree_difference, target_4, target_5)
and func_2(vtree_difference, target_4, target_2)
and func_3(vtree_difference, target_4, target_3)
and func_4(target_4)
and func_5(vtree_difference, target_5)
and vtree_difference.getType().hasName("int")
and not vtree_difference.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
