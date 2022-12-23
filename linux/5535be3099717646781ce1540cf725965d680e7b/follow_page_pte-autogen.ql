/**
 * @name linux-5535be3099717646781ce1540cf725965d680e7b-follow_page_pte
 * @id cpp/linux/5535be3099717646781ce1540cf725965d680e7b/follow_page_pte
 * @description linux-5535be3099717646781ce1540cf725965d680e7b-follow_page_pte CVE-2016-5195
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Variable vpage_496) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vpage_496
		and target_2.getRValue() instanceof Literal)
}

predicate func_3(Parameter vflags_492, Variable vpage_496, Variable vpte_498, Parameter vvma_491) {
	exists(GotoStmt target_3 |
		target_3.toString() = "goto ..."
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_492
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("can_follow_write_pte")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_498
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpage_496
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvma_491
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vflags_492)
}

predicate func_4(Parameter vflags_492, Variable vptl_497, Variable vptep_498, Variable vpte_498) {
	exists(DoStmt target_4 |
		target_4.getCondition().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptl_497
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableAccess).getTarget()=vptep_498
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_492
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("can_follow_write_pte")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_498
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vflags_492)
}

predicate func_5(Parameter vflags_492, Variable vpte_498) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_492
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("can_follow_write_pte")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_498
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vflags_492)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="0"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vptl_497, Variable vptep_498, Function func) {
	exists(DoStmt target_7 |
		target_7.getCondition() instanceof Literal
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptl_497
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableAccess).getTarget()=vptep_498
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_10(Parameter vflags_492, Parameter vvma_491) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("no_page_table")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vvma_491
		and target_10.getArgument(1).(VariableAccess).getTarget()=vflags_492)
}

from Function func, Parameter vflags_492, Variable vpage_496, Variable vptl_497, Variable vptep_498, Variable vpte_498, Parameter vvma_491
where
not func_2(vpage_496)
and not func_3(vflags_492, vpage_496, vpte_498, vvma_491)
and func_4(vflags_492, vptl_497, vptep_498, vpte_498)
and func_5(vflags_492, vpte_498)
and func_6(func)
and func_7(vptl_497, vptep_498, func)
and vflags_492.getType().hasName("unsigned int")
and vpage_496.getType().hasName("page *")
and vptl_497.getType().hasName("spinlock_t *")
and vptep_498.getType().hasName("pte_t *")
and vpte_498.getType().hasName("pte_t")
and vvma_491.getType().hasName("vm_area_struct *")
and func_10(vflags_492, vvma_491)
and vflags_492.getParentScope+() = func
and vpage_496.getParentScope+() = func
and vptl_497.getParentScope+() = func
and vptep_498.getParentScope+() = func
and vpte_498.getParentScope+() = func
and vvma_491.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
