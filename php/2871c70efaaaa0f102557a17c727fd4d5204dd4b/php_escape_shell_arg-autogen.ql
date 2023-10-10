/**
 * @name php-2871c70efaaaa0f102557a17c727fd4d5204dd4b-php_escape_shell_arg
 * @id cpp/php/2871c70efaaaa0f102557a17c727fd4d5204dd4b/php-escape-shell-arg
 * @description php-2871c70efaaaa0f102557a17c727fd4d5204dd4b-ext/standard/exec.c-php_escape_shell_arg CVE-2016-1904
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("zend_string_alloc")
		and not target_0.getTarget().hasName("zend_string_safe_alloc")
		and target_0.getArgument(0).(AddExpr).getAnOperand() instanceof MulExpr
		and target_0.getArgument(0).(AddExpr).getAnOperand() instanceof Literal
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("zend_string *")
		and target_0.getEnclosingFunction() = func
}

predicate func_2(Variable vl_343, VariableAccess target_2) {
		target_2.getTarget()=vl_343
		and target_2.getParent().(MulExpr).getParent().(AddExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Variable vl_343, AddExpr target_5, RelationalOperation target_6, MulExpr target_4) {
		target_4.getLeftOperand() instanceof Literal
		and target_4.getRightOperand().(VariableAccess).getTarget()=vl_343
		and target_4.getParent().(AddExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_5.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_4.getRightOperand().(VariableAccess).getLocation())
		and target_4.getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_5(Variable vl_343, AddExpr target_5) {
		target_5.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vl_343
		and target_5.getAnOperand().(Literal).getValue()="3"
}

predicate func_6(Variable vl_343, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vl_343
}

from Function func, Variable vl_343, FunctionCall target_0, VariableAccess target_2, MulExpr target_4, AddExpr target_5, RelationalOperation target_6
where
func_0(func, target_0)
and func_2(vl_343, target_2)
and func_4(vl_343, target_5, target_6, target_4)
and func_5(vl_343, target_5)
and func_6(vl_343, target_6)
and vl_343.getType().hasName("int")
and vl_343.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
