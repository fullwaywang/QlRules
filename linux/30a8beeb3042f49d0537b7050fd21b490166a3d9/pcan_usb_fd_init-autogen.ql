/**
 * @name linux-30a8beeb3042f49d0537b7050fd21b490166a3d9-pcan_usb_fd_init
 * @id cpp/linux/30a8beeb3042f49d0537b7050fd21b490166a3d9/pcan-usb-fd-init
 * @description linux-30a8beeb3042f49d0537b7050fd21b490166a3d9-pcan_usb_fd_init 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kmalloc")
		and not target_0.getTarget().hasName("kzalloc")
		and target_0.getArgument(0).(Literal).getValue()="512"
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
