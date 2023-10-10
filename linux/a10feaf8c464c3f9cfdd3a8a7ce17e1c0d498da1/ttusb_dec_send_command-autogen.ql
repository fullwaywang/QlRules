/**
 * @name linux-a10feaf8c464c3f9cfdd3a8a7ce17e1c0d498da1-ttusb_dec_send_command
 * @id cpp/linux/a10feaf8c464c3f9cfdd3a8a7ce17e1c0d498da1/ttusb-dec-send-command
 * @description linux-a10feaf8c464c3f9cfdd3a8a7ce17e1c0d498da1-ttusb_dec_send_command 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kmalloc")
		and not target_0.getTarget().hasName("kzalloc")
		and target_0.getArgument(0).(AddExpr).getValue()="64"
		and target_0.getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="60"
		and target_0.getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_0.getArgument(1).(BitwiseOrExpr).getValue()="3264"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3072"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_0.getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
