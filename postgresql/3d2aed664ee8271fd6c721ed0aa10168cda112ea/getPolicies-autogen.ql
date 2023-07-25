/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-getPolicies
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/getPolicies
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-getPolicies CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtbinfo_3438, Parameter vfout_3414, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("selectSourceSchema")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_3414
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_3438
}

from Function func, Variable vtbinfo_3438, Parameter vfout_3414, ExprStmt target_0
where
func_0(vtbinfo_3438, vfout_3414, target_0)
and vtbinfo_3438.getType().hasName("TableInfo *")
and vfout_3414.getType().hasName("Archive *")
and vtbinfo_3438.(LocalVariable).getFunction() = func
and vfout_3414.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
