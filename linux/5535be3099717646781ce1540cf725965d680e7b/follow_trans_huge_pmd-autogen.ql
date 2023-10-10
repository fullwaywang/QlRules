/**
 * @name linux-5535be3099717646781ce1540cf725965d680e7b-follow_trans_huge_pmd
 * @id cpp/linux/5535be3099717646781ce1540cf725965d680e7b/follow_trans_huge_pmd
 * @description linux-5535be3099717646781ce1540cf725965d680e7b-follow_trans_huge_pmd CVE-2016-5195
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1005"
		and not target_0.getValue()="1001"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1006"
		and not target_1.getValue()="1002"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1007"
		and not target_2.getValue()="1003"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1008"
		and not target_3.getValue()="1004"
		and target_3.getEnclosingFunction() = func)
}

predicate func_7(Variable vpage_1414, Parameter vpmd_1410, Parameter vflags_1411, Parameter vvma_1408) {
	exists(ReturnStmt target_7 |
		target_7.getExpr() instanceof Literal
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_1411
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("can_follow_write_pmd")
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmd_1410
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpage_1414
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvma_1408
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vflags_1411)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="0"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Initializer target_11 |
		target_11.getExpr() instanceof Literal
		and target_11.getExpr().getEnclosingFunction() = func)
}

predicate func_12(Parameter vflags_1411) {
	exists(GotoStmt target_12 |
		target_12.toString() = "goto ..."
		and target_12.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_1411
		and target_12.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_12.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("can_follow_write_pmd")
		and target_12.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof PointerDereferenceExpr
		and target_12.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vflags_1411)
}

predicate func_14(Function func) {
	exists(LabelStmt target_14 |
		target_14.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

predicate func_15(Variable vmm_1413, Parameter vpmd_1410) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("pmd_lockptr")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vmm_1413
		and target_15.getArgument(1).(VariableAccess).getTarget()=vpmd_1410)
}

predicate func_16(Parameter vvma_1408) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="vm_mm"
		and target_16.getQualifier().(VariableAccess).getTarget()=vvma_1408)
}

from Function func, Variable vmm_1413, Variable vpage_1414, Parameter vpmd_1410, Parameter vflags_1411, Parameter vvma_1408
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and not func_7(vpage_1414, vpmd_1410, vflags_1411, vvma_1408)
and func_10(func)
and func_11(func)
and func_12(vflags_1411)
and func_14(func)
and vpage_1414.getType().hasName("page *")
and vpmd_1410.getType().hasName("pmd_t *")
and func_15(vmm_1413, vpmd_1410)
and vflags_1411.getType().hasName("unsigned int")
and vvma_1408.getType().hasName("vm_area_struct *")
and func_16(vvma_1408)
and vmm_1413.getParentScope+() = func
and vpage_1414.getParentScope+() = func
and vpmd_1410.getParentScope+() = func
and vflags_1411.getParentScope+() = func
and vvma_1408.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
