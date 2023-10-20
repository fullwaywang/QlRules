/**
 * @name php-9c3171f019d07b4271c5929478dddba0861e92af-phar_parse_zipfile
 * @id cpp/php/9c3171f019d07b4271c5929478dddba0861e92af/phar-parse-zipfile
 * @description php-9c3171f019d07b4271c5929478dddba0861e92af-ext/phar/zip.c-phar_parse_zipfile CVE-2020-7068
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmydata_179, Variable vphar_globals, VariableAccess target_2, ExprStmt target_3, ExprStmt target_1, AddressOfExpr target_4, AddressOfExpr target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("zend_hash_str_add_ptr")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="phar_alias_map"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vphar_globals
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="alias"
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmydata_179
		and target_0.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="alias_len"
		and target_0.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmydata_179
		and target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmydata_179
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmydata_179, Variable vactual_alias_181, Variable vphar_globals, VariableAccess target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("zend_hash_str_add_ptr")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="phar_alias_map"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vphar_globals
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_alias_181
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="alias_len"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmydata_179
		and target_1.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmydata_179
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vactual_alias_181, VariableAccess target_2) {
		target_2.getTarget()=vactual_alias_181
}

predicate func_3(Variable vmydata_179, Variable vactual_alias_181, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alias"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmydata_179
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="is_persistent"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("zend_strndup")
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vactual_alias_181
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="alias_len"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmydata_179
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("_estrndup")
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vactual_alias_181
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="alias_len"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmydata_179
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vactual_alias_181
}

predicate func_4(Variable vphar_globals, AddressOfExpr target_4) {
		target_4.getOperand().(ValueFieldAccess).getTarget().getName()="phar_fname_map"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vphar_globals
}

predicate func_5(Variable vphar_globals, AddressOfExpr target_5) {
		target_5.getOperand().(ValueFieldAccess).getTarget().getName()="phar_alias_map"
		and target_5.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vphar_globals
}

from Function func, Variable vmydata_179, Variable vactual_alias_181, Variable vphar_globals, ExprStmt target_1, VariableAccess target_2, ExprStmt target_3, AddressOfExpr target_4, AddressOfExpr target_5
where
not func_0(vmydata_179, vphar_globals, target_2, target_3, target_1, target_4, target_5)
and func_1(vmydata_179, vactual_alias_181, vphar_globals, target_2, target_1)
and func_2(vactual_alias_181, target_2)
and func_3(vmydata_179, vactual_alias_181, target_3)
and func_4(vphar_globals, target_4)
and func_5(vphar_globals, target_5)
and vmydata_179.getType().hasName("phar_archive_data *")
and vactual_alias_181.getType().hasName("char *")
and vphar_globals.getType().hasName("zend_phar_globals")
and vmydata_179.getParentScope+() = func
and vactual_alias_181.getParentScope+() = func
and not vphar_globals.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
