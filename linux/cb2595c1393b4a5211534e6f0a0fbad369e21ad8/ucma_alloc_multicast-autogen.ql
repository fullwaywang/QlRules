/**
 * @name linux-cb2595c1393b4a5211534e6f0a0fbad369e21ad8-ucma_alloc_multicast
 * @id cpp/linux/cb2595c1393b4a5211534e6f0a0fbad369e21ad8/ucma_alloc_multicast
 * @description linux-cb2595c1393b4a5211534e6f0a0fbad369e21ad8-ucma_alloc_multicast 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vmc_231, Variable vmulticast_idr) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vmc_231
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("idr_alloc")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmulticast_idr
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getValue()="20971712"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="20971584"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="4194304"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="16777216"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

from Function func, Variable vmc_231, Variable vmulticast_idr
where
func_1(vmc_231, vmulticast_idr)
and vmc_231.getType().hasName("ucma_multicast *")
and vmulticast_idr.getType().hasName("idr")
and vmc_231.getParentScope+() = func
and not vmulticast_idr.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
