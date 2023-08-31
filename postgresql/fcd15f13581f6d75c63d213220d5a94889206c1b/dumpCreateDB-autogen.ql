/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-dumpCreateDB
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/dumpCreateDB
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_dump/pg_dumpall.c-dumpCreateDB CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfdbname_1434, Variable vbuf_1257, FunctionCall target_0) {
		target_0.getTarget().hasName("appendPQExpBuffer")
		and not target_0.getTarget().hasName("appendPsqlMetaConnect")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_1257
		and target_0.getArgument(1).(StringLiteral).getValue()="\\connect %s\n"
		and target_0.getArgument(2).(VariableAccess).getTarget()=vfdbname_1434
}

from Function func, Variable vfdbname_1434, Variable vbuf_1257, FunctionCall target_0
where
func_0(vfdbname_1434, vbuf_1257, target_0)
and vfdbname_1434.getType().hasName("char *")
and vbuf_1257.getType().hasName("PQExpBuffer")
and vfdbname_1434.(LocalVariable).getFunction() = func
and vbuf_1257.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
