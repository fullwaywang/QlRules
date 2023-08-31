/**
 * @name postgresql-de494ec14f6bd7f2676623a5934723a6c8ba51c2-execute_extension_script
 * @id cpp/postgresql/de494ec14f6bd7f2676623a5934723a6c8ba51c2/execute-extension-script
 * @description postgresql-de494ec14f6bd7f2676623a5934723a6c8ba51c2-src/backend/commands/extension.c-execute_extension_script CVE-2023-39417
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vuserName_997, FunctionCall target_2, FunctionCall target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("strpbrk")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vuserName_997
		and target_0.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char *")
		and target_0.getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errstart_cold")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errstart")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vschemaName_851, Variable vt_sql_974, NotExpr target_4, FunctionCall target_5, ExprStmt target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vt_sql_974
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("Datum")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("strpbrk")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vschemaName_851
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char *")
		and target_1.getThen().(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errstart_cold")
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errstart")
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_1.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(FunctionCall target_2) {
		target_2.getTarget().hasName("strstr")
		and target_2.getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getArgument(1).(StringLiteral).getValue()="@extowner@"
}

predicate func_3(Variable vuserName_997, FunctionCall target_3) {
		target_3.getTarget().hasName("quote_identifier")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vuserName_997
}

predicate func_4(NotExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="relocatable"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ExtensionControlFile *")
}

predicate func_5(Parameter vschemaName_851, FunctionCall target_5) {
		target_5.getTarget().hasName("quote_identifier")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vschemaName_851
}

predicate func_6(Variable vt_sql_974, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_sql_974
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DirectFunctionCall3Coll")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="950"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt_sql_974
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("cstring_to_text")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(StringLiteral).getValue()="@extschema@"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("cstring_to_text")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
}

from Function func, Parameter vschemaName_851, Variable vt_sql_974, Variable vuserName_997, FunctionCall target_2, FunctionCall target_3, NotExpr target_4, FunctionCall target_5, ExprStmt target_6
where
not func_0(vuserName_997, target_2, target_3)
and not func_1(vschemaName_851, vt_sql_974, target_4, target_5, target_6)
and func_2(target_2)
and func_3(vuserName_997, target_3)
and func_4(target_4)
and func_5(vschemaName_851, target_5)
and func_6(vt_sql_974, target_6)
and vschemaName_851.getType().hasName("const char *")
and vt_sql_974.getType().hasName("Datum")
and vuserName_997.getType().hasName("const char *")
and vschemaName_851.getFunction() = func
and vt_sql_974.(LocalVariable).getFunction() = func
and vuserName_997.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
