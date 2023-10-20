/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-getForeignDataWrappers
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/getForeignDataWrappers
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-getForeignDataWrappers CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfout_8921, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("selectSourceSchema")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_8921
		and target_0.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pg_catalog"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Parameter vfout_8921, ExprStmt target_0
where
func_0(vfout_8921, func, target_0)
and vfout_8921.getType().hasName("Archive *")
and vfout_8921.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
