/**
 * @name linux-307c8de2b02344805ebead3440d8feed28f2f010-xennet_alloc_one_rx_buffer
 * @id cpp/linux/307c8de2b02344805ebead3440d8feed28f2f010/xennet-alloc-one-rx-buffer
 * @description linux-307c8de2b02344805ebead3440d8feed28f2f010-xennet_alloc_one_rx_buffer CVE-2022-33740
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vqueue_263) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("page_pool_dev_alloc_pages")
		and not target_0.getTarget().hasName("page_pool_alloc_pages")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="page_pool"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_263)
}

predicate func_1(Parameter vqueue_263) {
	exists(BitwiseOrExpr target_1 |
		target_1.getValue()="11040"
		and target_1.getLeftOperand().(BitwiseOrExpr).getValue()="10784"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="2592"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="544"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="32"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="512"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8192"
		and target_1.getRightOperand().(Literal).getValue()="256"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("page_pool_alloc_pages")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="page_pool"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_263)
}

from Function func, Parameter vqueue_263
where
func_0(vqueue_263)
and not func_1(vqueue_263)
and vqueue_263.getType().hasName("netfront_queue *")
and vqueue_263.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
