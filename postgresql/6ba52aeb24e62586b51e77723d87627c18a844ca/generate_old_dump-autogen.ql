/**
 * @name postgresql-6ba52aeb24e62586b51e77723d87627c18a844ca-generate_old_dump
 * @id cpp/postgresql/6ba52aeb24e62586b51e77723d87627c18a844ca/generate-old-dump
 * @description postgresql-6ba52aeb24e62586b51e77723d87627c18a844ca-src/bin/pg_upgrade/dump.c-generate_old_dump CVE-2018-1053
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, DeclStmt target_0) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Variable vold_umask_21, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vold_umask_21
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("umask")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(BitwiseOrExpr).getValue()="63"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vold_umask_21, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("umask")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vold_umask_21
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Variable vold_umask_21, DeclStmt target_0, ExprStmt target_1, ExprStmt target_2
where
func_0(func, target_0)
and func_1(vold_umask_21, func, target_1)
and func_2(vold_umask_21, func, target_2)
and vold_umask_21.getType().hasName("mode_t")
and vold_umask_21.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
