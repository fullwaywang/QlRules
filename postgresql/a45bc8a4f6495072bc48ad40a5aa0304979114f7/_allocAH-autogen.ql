/**
 * @name postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-_allocAH
 * @id cpp/postgresql/a45bc8a4f6495072bc48ad40a5aa0304979114f7/-allocAH
 * @description postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-src/bin/pg_dump/pg_backup_archiver.c-_allocAH CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="664"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vAH_2268, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="promptPassword"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_2268
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Variable vAH_2268, SizeofTypeOperator target_0, ExprStmt target_1
where
func_0(func, target_0)
and func_1(vAH_2268, func, target_1)
and vAH_2268.getType().hasName("ArchiveHandle *")
and vAH_2268.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
