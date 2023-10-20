/**
 * @name php-0d13325b660b5ae64267dffcc9a153c7634fdfe2-php_uuencode
 * @id cpp/php/0d13325b660b5ae64267dffcc9a153c7634fdfe2/php-uuencode
 * @description php-0d13325b660b5ae64267dffcc9a153c7634fdfe2-ext/standard/uuencode.c-php_uuencode CVE-2016-7125
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("zend_string_alloc")
		and not target_0.getTarget().hasName("zend_string_safe_alloc")
		and target_0.getArgument(0).(AddExpr).getAnOperand() instanceof FunctionCall
		and target_0.getArgument(0).(AddExpr).getAnOperand() instanceof Literal
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("zend_string *")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vsrc_len_68, ExprStmt target_6) {
	exists(DivExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vsrc_len_68
		and target_1.getRightOperand().(Literal).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_1.getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsrc_len_68, VariableAccess target_3) {
		target_3.getTarget()=vsrc_len_68
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(AddExpr).getAnOperand() instanceof FunctionCall
}

predicate func_5(Parameter vsrc_len_68, FunctionCall target_5) {
		target_5.getTarget().hasName("ceil")
		and target_5.getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsrc_len_68
		and target_5.getArgument(0).(MulExpr).getRightOperand().(Literal).getValue()="1.379999999999999893"
		and target_5.getParent().(AddExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_6(Parameter vsrc_len_68, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsrc_len_68
}

from Function func, Parameter vsrc_len_68, FunctionCall target_0, VariableAccess target_3, FunctionCall target_5, ExprStmt target_6
where
func_0(func, target_0)
and not func_1(vsrc_len_68, target_6)
and func_3(vsrc_len_68, target_3)
and func_5(vsrc_len_68, target_5)
and func_6(vsrc_len_68, target_6)
and vsrc_len_68.getType().hasName("size_t")
and vsrc_len_68.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
