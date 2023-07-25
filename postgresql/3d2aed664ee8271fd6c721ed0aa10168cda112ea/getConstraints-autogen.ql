/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-getConstraints
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/getConstraints
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-getConstraints CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfout_7102, Variable vtbinfo_7120, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("selectSourceSchema")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_7102
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtbinfo_7120
}

from Function func, Parameter vfout_7102, Variable vtbinfo_7120, ExprStmt target_0
where
func_0(vfout_7102, vtbinfo_7120, target_0)
and vfout_7102.getType().hasName("Archive *")
and vtbinfo_7120.getType().hasName("TableInfo *")
and vfout_7102.getFunction() = func
and vtbinfo_7120.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
