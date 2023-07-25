/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-expand_table_name_patterns
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/expand-table-name-patterns
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/pg_dump/pg_dump.c-expand_table_name_patterns CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="SELECT c.oid\nFROM pg_catalog.pg_class c\n     LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace\nWHERE c.relkind in ('%c', '%c', '%c', '%c', '%c', '%c')\n"
		and not target_0.getValue()="SELECT c.oid\nFROM pg_catalog.pg_class c\n     LEFT JOIN pg_catalog.pg_namespace n\n     ON n.oid OPERATOR(pg_catalog.=) c.relnamespace\nWHERE c.relkind OPERATOR(pg_catalog.=) ANY\n    (array['%c', '%c', '%c', '%c', '%c', '%c'])\n"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vfout_1293, FunctionCall target_3, ExprStmt target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ExecuteSqlStatement")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_1293
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="RESET search_path"
		and target_3.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vfout_1293, ExprStmt target_4) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("PQclear")
		and target_2.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ExecuteSqlQueryForSingleRow")
		and target_2.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_1293
		and target_2.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT pg_catalog.set_config('search_path', '', false)"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vfout_1293, FunctionCall target_3) {
		target_3.getTarget().hasName("GetConnection")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vfout_1293
}

predicate func_4(Parameter vfout_1293, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PGresult *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecuteSqlQuery")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_1293
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PQExpBuffer")
}

from Function func, Parameter vfout_1293, StringLiteral target_0, FunctionCall target_3, ExprStmt target_4
where
func_0(func, target_0)
and not func_1(vfout_1293, target_3, target_4)
and not func_2(vfout_1293, target_4)
and func_3(vfout_1293, target_3)
and func_4(vfout_1293, target_4)
and vfout_1293.getType().hasName("Archive *")
and vfout_1293.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
