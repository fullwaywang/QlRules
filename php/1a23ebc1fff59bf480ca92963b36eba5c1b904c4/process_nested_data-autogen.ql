/**
 * @name php-1a23ebc1fff59bf480ca92963b36eba5c1b904c4-process_nested_data
 * @id cpp/php/1a23ebc1fff59bf480ca92963b36eba5c1b904c4/process-nested-data
 * @description php-1a23ebc1fff59bf480ca92963b36eba5c1b904c4-ext/standard/var_unserializer.c-process_nested_data CVE-2017-12932
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvar_hash_339, Variable vdata_342, FunctionCall target_5, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("var_push_dtor")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_hash_339
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_342
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_1(Parameter vht_339, Variable vkey_342, Variable vdata_342, IfStmt target_1) {
		target_1.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("zval_get_type")
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_342
		and target_1.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("zval_get_type")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkey_342
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zend_hash_index_del")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vht_339
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="lval"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zend_hash_del_ind")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vht_339
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="str"
		and target_1.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
}

/*predicate func_2(Parameter vht_339, Variable vkey_342, FunctionCall target_5, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("zval_get_type")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkey_342
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zend_hash_index_del")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vht_339
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="lval"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_342
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zend_hash_del_ind")
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vht_339
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="str"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_342
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

*/
/*predicate func_3(Parameter vht_339, Variable vkey_342, EqualityOperation target_6, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("zend_hash_index_del")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vht_339
		and target_3.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="lval"
		and target_3.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_3.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_342
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
/*predicate func_4(Parameter vht_339, Variable vkey_342, EqualityOperation target_6, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("zend_hash_del_ind")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vht_339
		and target_4.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="str"
		and target_4.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_4.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_342
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
predicate func_5(FunctionCall target_5) {
		target_5.getTarget().hasName("__builtin_expect")
		and target_5.getArgument(0) instanceof NotExpr
		and target_5.getArgument(1) instanceof Literal
}

predicate func_6(EqualityOperation target_6) {
		target_6.getAnOperand() instanceof FunctionCall
		and target_6.getAnOperand() instanceof Literal
}

from Function func, Parameter vvar_hash_339, Parameter vht_339, Variable vkey_342, Variable vdata_342, ExprStmt target_0, IfStmt target_1, FunctionCall target_5, EqualityOperation target_6
where
func_0(vvar_hash_339, vdata_342, target_5, target_0)
and func_1(vht_339, vkey_342, vdata_342, target_1)
and func_5(target_5)
and func_6(target_6)
and vvar_hash_339.getType().hasName("php_unserialize_data_t *")
and vht_339.getType().hasName("HashTable *")
and vkey_342.getType().hasName("zval")
and vdata_342.getType().hasName("zval *")
and vvar_hash_339.getFunction() = func
and vht_339.getFunction() = func
and vkey_342.(LocalVariable).getFunction() = func
and vdata_342.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
