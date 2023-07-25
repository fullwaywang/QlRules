/**
 * @name php-712fc54e856d3d8e80a7d074a2733bc6b3a27e90-php_pcre_replace_func_impl
 * @id cpp/php/712fc54e856d3d8e80a7d074a2733bc6b3a27e90/php-pcre-replace-func-impl
 * @description php-712fc54e856d3d8e80a7d074a2733bc6b3a27e90-ext/pcre/php_pcre.c-php_pcre_replace_func_impl CVE-2017-9118
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_len_1862, RelationalOperation target_6, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_len_1862
		and target_6.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_1(Variable vnew_len_1862, Variable veval_result_1870, ExprStmt target_7, RelationalOperation target_6, NotExpr target_8, ExprStmt target_9) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_result_1870
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(BitwiseAndExpr).getValue()="32"
		and target_1.getLeftOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_len_1862
		and target_1.getRightOperand().(BitwiseAndExpr).getValue()="32"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_len_1862
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_1.getLeftOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(VariableAccess).getLocation())
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vnew_len_1862, Variable veval_result_1870, NotExpr target_8, ExprStmt target_9) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_result_1870
		and target_2.getAnOperand().(BitwiseAndExpr).getValue()="32"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="len"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_result_1870
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_len_1862
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable vnew_len_1862, RelationalOperation target_6) {
	exists(SubExpr target_3 |
		target_3.getLeftOperand().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_3.getLeftOperand().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_3.getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_len_1862
		and target_3.getLeftOperand().(FunctionCall).getArgument(2).(BitwiseAndExpr).getValue()="32"
		and target_3.getRightOperand().(BitwiseAndExpr).getValue()="32"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_6.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vnew_len_1862) {
	exists(BitwiseAndExpr target_4 |
		target_4.getValue()="32"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_len_1862
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal)
}

*/
predicate func_5(Variable vnew_len_1862, Variable veval_result_1870, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="len"
		and target_5.getQualifier().(VariableAccess).getTarget()=veval_result_1870
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_len_1862
}

predicate func_6(Variable vnew_len_1862, RelationalOperation target_6) {
		 (target_6 instanceof GEExpr or target_6 instanceof LEExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vnew_len_1862
		and target_6.getLesserOperand().(VariableAccess).getTarget().getType().hasName("size_t")
}

predicate func_7(Variable vnew_len_1862, Variable veval_result_1870, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_len_1862
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zend_safe_address_guarded")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="len"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_result_1870
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnew_len_1862
}

predicate func_8(Variable veval_result_1870, NotExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=veval_result_1870
}

predicate func_9(Variable veval_result_1870, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="val"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("zend_string *")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="val"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_result_1870
		and target_9.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="len"
		and target_9.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_result_1870
}

from Function func, Variable vnew_len_1862, Variable veval_result_1870, Literal target_0, PointerFieldAccess target_5, RelationalOperation target_6, ExprStmt target_7, NotExpr target_8, ExprStmt target_9
where
func_0(vnew_len_1862, target_6, target_0)
and not func_1(vnew_len_1862, veval_result_1870, target_7, target_6, target_8, target_9)
and not func_3(vnew_len_1862, target_6)
and func_5(vnew_len_1862, veval_result_1870, target_5)
and func_6(vnew_len_1862, target_6)
and func_7(vnew_len_1862, veval_result_1870, target_7)
and func_8(veval_result_1870, target_8)
and func_9(veval_result_1870, target_9)
and vnew_len_1862.getType().hasName("size_t")
and veval_result_1870.getType().hasName("zend_string *")
and vnew_len_1862.(LocalVariable).getFunction() = func
and veval_result_1870.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
