/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-pg_get_indexdef_worker
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/pg-get-indexdef-worker
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/backend/utils/adt/ruleutils.c-pg_get_indexdef_worker CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vprettyFlags_1150, Variable vindrelid_1164, ExprStmt target_2, ExprStmt target_3, FunctionCall target_1) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vprettyFlags_1150
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getThen() instanceof FunctionCall
		and target_0.getElse().(FunctionCall).getTarget().hasName("generate_qualified_relation_name")
		and target_0.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindrelid_1164
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="CREATE %sINDEX %s ON %s%s USING %s ("
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="indisunique"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_index")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="UNIQUE "
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("quote_identifier")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="relname"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_class")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="relkind"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_class")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="73"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(StringLiteral).getValue()="ONLY "
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof FunctionCall
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getTarget().hasName("quote_identifier")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="amname"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_am")
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getElse().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getElse().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vindrelid_1164, FunctionCall target_1) {
		target_1.getTarget().hasName("generate_relation_name")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vindrelid_1164
		and target_1.getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="CREATE %sINDEX %s ON %s%s USING %s ("
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="indisunique"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_index")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="UNIQUE "
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("quote_identifier")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="relname"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_class")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="relkind"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_class")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="73"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(StringLiteral).getValue()="ONLY "
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getTarget().hasName("quote_identifier")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="amname"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Form_pg_am")
}

predicate func_2(Parameter vprettyFlags_1150, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("deparse_expression_pretty")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Node *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("List *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprettyFlags_1150
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_3(Variable vindrelid_1164, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("List *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("deparse_context_for")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("get_relation_name")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindrelid_1164
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vindrelid_1164
}

from Function func, Parameter vprettyFlags_1150, Variable vindrelid_1164, FunctionCall target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vprettyFlags_1150, vindrelid_1164, target_2, target_3, target_1)
and func_1(vindrelid_1164, target_1)
and func_2(vprettyFlags_1150, target_2)
and func_3(vindrelid_1164, target_3)
and vprettyFlags_1150.getType().hasName("int")
and vindrelid_1164.getType().hasName("Oid")
and vprettyFlags_1150.getFunction() = func
and vindrelid_1164.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
