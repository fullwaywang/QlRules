/**
 * @name libjpeg-turbo-3de15e0c344d11d4b90f4a47136467053eb2d09a-start_input_ppm
 * @id cpp/libjpeg-turbo/3de15e0c344d11d4b90f4a47136467053eb2d09a/start-input-ppm
 * @description libjpeg-turbo-3de15e0c344d11d4b90f4a47136467053eb2d09a-rdppm.c-start_input_ppm CVE-2020-13790
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_7(Variable vmaxval_565, MulExpr target_9) {
	exists(ConditionalExpr target_7 |
		target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmaxval_565
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_7.getThen().(VariableAccess).getTarget()=vmaxval_565
		and target_7.getElse().(Literal).getValue()="255"
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vmaxval_565, VariableAccess target_8) {
		target_8.getTarget()=vmaxval_565
}

predicate func_9(Variable vmaxval_565, MulExpr target_9) {
		target_9.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmaxval_565
		and target_9.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

from Function func, Variable vmaxval_565, VariableAccess target_8, MulExpr target_9
where
not func_7(vmaxval_565, target_9)
and func_8(vmaxval_565, target_8)
and func_9(vmaxval_565, target_9)
and vmaxval_565.getType().hasName("unsigned int")
and vmaxval_565.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
