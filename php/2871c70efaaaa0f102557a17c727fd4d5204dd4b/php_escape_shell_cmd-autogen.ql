/**
 * @name php-2871c70efaaaa0f102557a17c727fd4d5204dd4b-php_escape_shell_cmd
 * @id cpp/php/2871c70efaaaa0f102557a17c727fd4d5204dd4b/php-escape-shell-cmd
 * @description php-2871c70efaaaa0f102557a17c727fd4d5204dd4b-ext/standard/exec.c-php_escape_shell_cmd CVE-2016-1904
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_248, FunctionCall target_0) {
		target_0.getTarget().hasName("zend_string_alloc")
		and not target_0.getTarget().hasName("zend_string_safe_alloc")
		and target_0.getArgument(0).(MulExpr).getLeftOperand() instanceof Literal
		and target_0.getArgument(0).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vl_248
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("zend_string *")
}

predicate func_3(Variable vl_248, VariableAccess target_3) {
		target_3.getTarget()=vl_248
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

from Function func, Variable vl_248, FunctionCall target_0, VariableAccess target_3
where
func_0(vl_248, target_0)
and func_3(vl_248, target_3)
and vl_248.getType().hasName("int")
and vl_248.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
