/**
 * @name linux-48900cb6af4282fa0fb6ff4d72a81aa3dadb5c39-virtnet_probe
 * @id cpp/linux/48900cb6af4282fa0fb6ff4d72a81aa3dadb5c39/virtnet_probe
 * @description linux-48900cb6af4282fa0fb6ff4d72a81aa3dadb5c39-virtnet_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="9"
		and target_0.getLeftOperand().(BinaryBitwiseOperation).getValue()="8"
		and target_0.getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_0.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(BitwiseOrExpr target_2 |
		target_2.getValue()="73"
		and target_2.getLeftOperand() instanceof BitwiseOrExpr
		and target_2.getRightOperand().(BinaryBitwiseOperation).getValue()="64"
		and target_2.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_2(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
