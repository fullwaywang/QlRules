/**
 * @name postgresql-37a795a60-populate_record_field
 * @id cpp/postgresql/37a795a60/populate-record-field
 * @description postgresql-37a795a60-src/backend/utils/adt/jsonfuncs.c-populate_record_field CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vtypcat_2934, Parameter vjsv_2931, ExprStmt target_9, ExprStmt target_10) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof LogicalOrExpr
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypcat_2934
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="is_json"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjsv_2931
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="json"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="jsonb"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjsv_2931
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="jsonb"
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalOrExpr
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtypcat_2934, ReturnStmt target_12, ExprStmt target_9, LogicalAndExpr target_6) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof LogicalAndExpr
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypcat_2934
		and target_2.getParent().(IfStmt).getThen()=target_12
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vtypmod_2927, Parameter vjsv_2931, Parameter visnull_2932, LogicalAndExpr target_6, PointerDereferenceExpr target_13) {
	exists(PointerDereferenceExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=visnull_2932
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("populate_composite")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="composite"
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ColumnIOData *")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypmod_2927
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("MemoryContext")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("Datum")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("pg_detoast_datum")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Datum")
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vjsv_2931
		and target_6.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_13.getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vtypcat_2934, Parameter vjsv_2931, ExprStmt target_9, LogicalOrExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypcat_2934
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypcat_2934
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="is_json"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjsv_2931
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="json"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="jsonb"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjsv_2931
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="jsonb"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_6(Variable vtypcat_2934, Parameter visnull_2932, ReturnStmt target_12, LogicalAndExpr target_6) {
		target_6.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=visnull_2932
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypcat_2934
		and target_6.getParent().(IfStmt).getThen()=target_12
}

predicate func_7(Parameter vjsv_2931, ExprStmt target_14, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="is_json"
		and target_7.getQualifier().(VariableAccess).getTarget()=vjsv_2931
		and target_7.getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_8(Parameter vtypmod_2927, Parameter vjsv_2931, FunctionCall target_15, FunctionCall target_16, FunctionCall target_17, VariableAccess target_8) {
		target_8.getTarget()=vtypmod_2927
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("populate_composite")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="composite"
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ColumnIOData *")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("MemoryContext")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("Datum")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("pg_detoast_datum")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Datum")
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vjsv_2931
		and target_15.getArgument(2).(VariableAccess).getLocation().isBefore(target_8.getLocation())
		and target_16.getArgument(3).(VariableAccess).getLocation().isBefore(target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation())
		and target_8.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_17.getArgument(4).(VariableAccess).getLocation())
}

predicate func_9(Variable vtypcat_2934, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypcat_2934
}

predicate func_10(Variable vtypcat_2934, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypcat_2934
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="typcat"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ColumnIOData *")
}

predicate func_12(ReturnStmt target_12) {
		target_12.getExpr().(Literal).getValue()="0"
}

predicate func_13(Parameter visnull_2932, PointerDereferenceExpr target_13) {
		target_13.getOperand().(VariableAccess).getTarget()=visnull_2932
}

predicate func_14(Parameter vjsv_2931, Parameter visnull_2932, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=visnull_2932
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="is_json"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjsv_2931
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="str"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="json"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="json"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="jsonb"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_14.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="jsonb"
}

predicate func_15(Parameter vtypmod_2927, Parameter vjsv_2931, FunctionCall target_15) {
		target_15.getTarget().hasName("populate_scalar")
		and target_15.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="scalar_io"
		and target_15.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ColumnIOData *")
		and target_15.getArgument(1).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_15.getArgument(2).(VariableAccess).getTarget()=vtypmod_2927
		and target_15.getArgument(3).(VariableAccess).getTarget()=vjsv_2931
}

predicate func_16(Parameter vjsv_2931, FunctionCall target_16) {
		target_16.getTarget().hasName("populate_array")
		and target_16.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="array"
		and target_16.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_16.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ColumnIOData *")
		and target_16.getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_16.getArgument(2).(VariableAccess).getTarget().getType().hasName("MemoryContext")
		and target_16.getArgument(3).(VariableAccess).getTarget()=vjsv_2931
}

predicate func_17(Parameter vjsv_2931, Parameter visnull_2932, FunctionCall target_17) {
		target_17.getTarget().hasName("populate_domain")
		and target_17.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="domain"
		and target_17.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_17.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ColumnIOData *")
		and target_17.getArgument(1).(VariableAccess).getTarget().getType().hasName("Oid")
		and target_17.getArgument(2).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_17.getArgument(3).(VariableAccess).getTarget().getType().hasName("MemoryContext")
		and target_17.getArgument(4).(VariableAccess).getTarget()=vjsv_2931
		and target_17.getArgument(5).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=visnull_2932
}

from Function func, Variable vtypcat_2934, Parameter vtypmod_2927, Parameter vjsv_2931, Parameter visnull_2932, LogicalOrExpr target_5, LogicalAndExpr target_6, PointerFieldAccess target_7, VariableAccess target_8, ExprStmt target_9, ExprStmt target_10, ReturnStmt target_12, PointerDereferenceExpr target_13, ExprStmt target_14, FunctionCall target_15, FunctionCall target_16, FunctionCall target_17
where
not func_1(vtypcat_2934, vjsv_2931, target_9, target_10)
and not func_2(vtypcat_2934, target_12, target_9, target_6)
and not func_4(vtypmod_2927, vjsv_2931, visnull_2932, target_6, target_13)
and func_5(vtypcat_2934, vjsv_2931, target_9, target_5)
and func_6(vtypcat_2934, visnull_2932, target_12, target_6)
and func_7(vjsv_2931, target_14, target_7)
and func_8(vtypmod_2927, vjsv_2931, target_15, target_16, target_17, target_8)
and func_9(vtypcat_2934, target_9)
and func_10(vtypcat_2934, target_10)
and func_12(target_12)
and func_13(visnull_2932, target_13)
and func_14(vjsv_2931, visnull_2932, target_14)
and func_15(vtypmod_2927, vjsv_2931, target_15)
and func_16(vjsv_2931, target_16)
and func_17(vjsv_2931, visnull_2932, target_17)
and vtypcat_2934.getType().hasName("TypeCat")
and vtypmod_2927.getType().hasName("int32")
and vjsv_2931.getType().hasName("JsValue *")
and visnull_2932.getType().hasName("bool *")
and vtypcat_2934.(LocalVariable).getFunction() = func
and vtypmod_2927.getFunction() = func
and vjsv_2931.getFunction() = func
and visnull_2932.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
