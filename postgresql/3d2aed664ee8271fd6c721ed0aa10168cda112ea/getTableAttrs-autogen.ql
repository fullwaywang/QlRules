/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-getTableAttrs
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/getTableAttrs
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-getTableAttrs CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtbinfo_8122, ValueFieldAccess target_0) {
		target_0.getTarget().getName()="namespace"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_8122
}

predicate func_1(Parameter vfout_8093, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("selectSourceSchema")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_8093
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier() instanceof ValueFieldAccess
}

from Function func, Parameter vfout_8093, Variable vtbinfo_8122, ValueFieldAccess target_0, ExprStmt target_1
where
func_0(vtbinfo_8122, target_0)
and func_1(vfout_8093, target_1)
and vfout_8093.getType().hasName("Archive *")
and vtbinfo_8122.getType().hasName("TableInfo *")
and vfout_8093.getFunction() = func
and vtbinfo_8122.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
