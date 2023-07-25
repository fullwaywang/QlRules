/**
 * @name sqlite3-527cbd4a104cb93bf3994b3dd3619a6299a78b13-sqlite3CheckObjectName
 * @id cpp/sqlite3/527cbd4a104cb93bf3994b3dd3619a6299a78b13/sqlite3CheckObjectName
 * @description sqlite3-527cbd4a104cb93bf3994b3dd3619a6299a78b13-src/build.c-sqlite3CheckObjectName CVE-2019-19603
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vzName_839, Variable vdb_843, BlockStmt target_2, LogicalOrExpr target_3, LogicalAndExpr target_1, ArrayExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3ReadOnlyShadowTables")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_843
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3ShadowTableName")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_843
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vzName_839
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vzName_839, Parameter vpParse_838, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nested"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_838
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3_strnicmp")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzName_839
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="sqlite_"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vzName_839, Parameter vpParse_838, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sqlite3ErrorMsg")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_838
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="object name reserved for internal use: %s"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vzName_839
		and target_2.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_3(Parameter vzName_839, Variable vdb_843, LogicalOrExpr target_3) {
		target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3_stricmp")
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="azInit"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="init"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_843
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqlite3_stricmp")
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzName_839
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="azInit"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="init"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_843
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getAnOperand().(FunctionCall).getTarget().hasName("sqlite3_stricmp")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="azInit"
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="init"
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_843
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

predicate func_4(Variable vdb_843, ArrayExpr target_4) {
		target_4.getArrayBase().(ValueFieldAccess).getTarget().getName()="azInit"
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="init"
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_843
		and target_4.getArrayOffset().(Literal).getValue()="2"
}

from Function func, Parameter vzName_839, Variable vdb_843, Parameter vpParse_838, LogicalAndExpr target_1, BlockStmt target_2, LogicalOrExpr target_3, ArrayExpr target_4
where
not func_0(vzName_839, vdb_843, target_2, target_3, target_1, target_4)
and func_1(vzName_839, vpParse_838, target_2, target_1)
and func_2(vzName_839, vpParse_838, target_2)
and func_3(vzName_839, vdb_843, target_3)
and func_4(vdb_843, target_4)
and vzName_839.getType().hasName("const char *")
and vdb_843.getType().hasName("sqlite3 *")
and vpParse_838.getType().hasName("Parse *")
and vzName_839.getFunction() = func
and vdb_843.(LocalVariable).getFunction() = func
and vpParse_838.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
