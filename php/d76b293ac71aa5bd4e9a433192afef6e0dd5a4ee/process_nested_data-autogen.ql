/**
 * @name php-d76b293ac71aa5bd4e9a433192afef6e0dd5a4ee-process_nested_data
 * @id cpp/php/d76b293ac71aa5bd4e9a433192afef6e0dd5a4ee/process-nested-data
 * @description php-d76b293ac71aa5bd4e9a433192afef6e0dd5a4ee-ext/standard/var_unserializer.c-process_nested_data CVE-2015-2787
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_328, Parameter vvar_hash_325, NotExpr target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("var_push_dtor")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_hash_325
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_328
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_328, Parameter vvar_hash_325, NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("php_var_unserialize_ex")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_328
		and target_1.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const unsigned char **")
		and target_1.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("const unsigned char *")
		and target_1.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vvar_hash_325
		and target_1.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("HashTable *")
}

from Function func, Variable vdata_328, Parameter vvar_hash_325, NotExpr target_1
where
not func_0(vdata_328, vvar_hash_325, target_1)
and func_1(vdata_328, vvar_hash_325, target_1)
and vdata_328.getType().hasName("zval *")
and vvar_hash_325.getType().hasName("php_unserialize_data_t *")
and vdata_328.(LocalVariable).getFunction() = func
and vvar_hash_325.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
