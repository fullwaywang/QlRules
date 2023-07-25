/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-getCasts
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/getCasts
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-getCasts CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfout_7877, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("selectSourceSchema")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_7877
		and target_0.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pg_catalog"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Parameter vfout_7877, ExprStmt target_0
where
func_0(vfout_7877, func, target_0)
and vfout_7877.getType().hasName("Archive *")
and vfout_7877.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
