/**
 * @name postgresql-919ebb023e74546c6293352556365091c5402366-execute_extension_script
 * @id cpp/postgresql/919ebb023e74546c6293352556365091c5402366/execute-extension-script
 * @description postgresql-919ebb023e74546c6293352556365091c5402366-src/backend/commands/extension.c-execute_extension_script CVE-2023-39417
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vschemaName_790, Variable v__func__, Variable vt_sql_888, NotExpr target_1, FunctionCall target_2, FunctionCall target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vt_sql_888
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("Datum")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("strpbrk")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vschemaName_790
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char *")
		and target_0.getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="relocatable"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ExtensionControlFile *")
}

predicate func_2(Parameter vschemaName_790, FunctionCall target_2) {
		target_2.getTarget().hasName("quote_identifier")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vschemaName_790
}

predicate func_3(Variable v__func__, FunctionCall target_3) {
		target_3.getTarget().hasName("errstart")
		and target_3.getArgument(0) instanceof Literal
		and target_3.getArgument(1) instanceof StringLiteral
		and target_3.getArgument(2) instanceof Literal
		and target_3.getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_3.getArgument(4) instanceof Literal
}

predicate func_4(Variable vt_sql_888, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_sql_888
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DirectFunctionCall3Coll")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt_sql_888
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("cstring_to_text")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(StringLiteral).getValue()="@extschema@"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("cstring_to_text")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
}

from Function func, Parameter vschemaName_790, Variable v__func__, Variable vt_sql_888, NotExpr target_1, FunctionCall target_2, FunctionCall target_3, ExprStmt target_4
where
not func_0(vschemaName_790, v__func__, vt_sql_888, target_1, target_2, target_3, target_4)
and func_1(target_1)
and func_2(vschemaName_790, target_2)
and func_3(v__func__, target_3)
and func_4(vt_sql_888, target_4)
and vschemaName_790.getType().hasName("const char *")
and v__func__.getType() instanceof ArrayType
and vt_sql_888.getType().hasName("Datum")
and vschemaName_790.getFunction() = func
and not v__func__.getParentScope+() = func
and vt_sql_888.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
