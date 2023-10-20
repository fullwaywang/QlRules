/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-getOpfamilies
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/getOpfamilies
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-getOpfamilies CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfout_5296, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("selectSourceSchema")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_5296
		and target_0.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="pg_catalog"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Parameter vfout_5296, ExprStmt target_0
where
func_0(vfout_5296, func, target_0)
and vfout_5296.getType().hasName("Archive *")
and vfout_5296.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
