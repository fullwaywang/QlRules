/**
 * @name php-712fc54e856d3d8e80a7d074a2733bc6b3a27e90-php_pcre_replace_impl
 * @id cpp/php/712fc54e856d3d8e80a7d074a2733bc6b3a27e90/php-pcre-replace-impl
 * @description php-712fc54e856d3d8e80a7d074a2733bc6b3a27e90-ext/pcre/php_pcre.c-php_pcre_replace_impl CVE-2017-9118
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_len_1621, RelationalOperation target_3, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_len_1621
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_1(Variable vnew_len_1621, RelationalOperation target_3) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_len_1621
		and target_1.getLeftOperand().(FunctionCall).getArgument(2).(BitwiseAndExpr).getValue()="32"
		and target_1.getRightOperand().(BitwiseAndExpr).getValue()="32"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vnew_len_1621) {
	exists(BitwiseAndExpr target_2 |
		target_2.getValue()="32"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_len_1621
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal)
}

*/
predicate func_3(Variable vnew_len_1621, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vnew_len_1621
		and target_3.getLesserOperand().(VariableAccess).getTarget().getType().hasName("size_t")
}

from Function func, Variable vnew_len_1621, Literal target_0, RelationalOperation target_3
where
func_0(vnew_len_1621, target_3, target_0)
and not func_1(vnew_len_1621, target_3)
and func_3(vnew_len_1621, target_3)
and vnew_len_1621.getType().hasName("size_t")
and vnew_len_1621.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
