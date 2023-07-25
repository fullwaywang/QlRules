/**
 * @name php-0d13325b660b5ae64267dffcc9a153c7634fdfe2-php_base64_encode
 * @id cpp/php/0d13325b660b5ae64267dffcc9a153c7634fdfe2/php-base64-encode
 * @description php-0d13325b660b5ae64267dffcc9a153c7634fdfe2-ext/standard/base64.c-php_base64_encode CVE-2016-7125
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("zend_string_alloc")
		and not target_0.getTarget().hasName("zend_string_safe_alloc")
		and target_0.getArgument(0).(MulExpr).getLeftOperand() instanceof MulExpr
		and target_0.getArgument(0).(MulExpr).getRightOperand() instanceof SizeofTypeOperator
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("zend_string *")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(MulExpr target_1 |
		target_1.getValue()="4"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Parameter vlength_56, DivExpr target_3) {
		target_3.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlength_56
		and target_3.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_3.getRightOperand().(Literal).getValue()="3"
		and target_3.getParent().(MulExpr).getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Function func, SizeofTypeOperator target_4) {
		target_4.getType() instanceof LongType
		and target_4.getValue()="1"
		and target_4.getEnclosingFunction() = func
}

predicate func_6(Function func, MulExpr target_6) {
		target_6.getLeftOperand() instanceof DivExpr
		and target_6.getRightOperand() instanceof Literal
		and target_6.getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_6.getEnclosingFunction() = func
}

from Function func, Parameter vlength_56, FunctionCall target_0, DivExpr target_3, SizeofTypeOperator target_4, MulExpr target_6
where
func_0(func, target_0)
and not func_1(func)
and func_3(vlength_56, target_3)
and func_4(func, target_4)
and func_6(func, target_6)
and vlength_56.getType().hasName("size_t")
and vlength_56.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
