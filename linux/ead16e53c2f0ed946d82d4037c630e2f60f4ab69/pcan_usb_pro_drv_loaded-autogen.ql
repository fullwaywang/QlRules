/**
 * @name linux-ead16e53c2f0ed946d82d4037c630e2f60f4ab69-pcan_usb_pro_drv_loaded
 * @id cpp/linux/ead16e53c2f0ed946d82d4037c630e2f60f4ab69/pcan_usb_pro_drv_loaded
 * @description linux-ead16e53c2f0ed946d82d4037c630e2f60f4ab69-pcan_usb_pro_drv_loaded 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kmalloc")
		and not target_0.getTarget().hasName("kzalloc")
		and target_0.getArgument(0).(Literal).getValue()="16"
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
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
