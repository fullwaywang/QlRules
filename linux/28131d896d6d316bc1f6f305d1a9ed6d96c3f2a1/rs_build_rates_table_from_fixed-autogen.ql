/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_build_rates_table_from_fixed
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rs-build-rates-table-from-fixed
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_build_rates_table_from_fixed CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="49152"
		and target_0.getLeftOperand().(BinaryBitwiseOperation).getValue()="16384"
		and target_0.getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="14"
		and target_0.getRightOperand().(BinaryBitwiseOperation).getValue()="32768"
		and target_0.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_0.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="14"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="14"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(BitwiseOrExpr target_2 |
		target_2.getValue()="114688"
		and target_2.getLeftOperand() instanceof BitwiseOrExpr
		and target_2.getRightOperand().(BinaryBitwiseOperation).getValue()="65536"
		and target_2.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="4"
		and target_2.getRightOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_2.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
