/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-getDomainConstraints
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/getDomainConstraints
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_dump.c-getDomainConstraints CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfout_7189, Parameter vtyinfo_7189, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("selectSourceSchema")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfout_7189
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="namespace"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dobj"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtyinfo_7189
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Parameter vfout_7189, Parameter vtyinfo_7189, ExprStmt target_0
where
func_0(vfout_7189, vtyinfo_7189, func, target_0)
and vfout_7189.getType().hasName("Archive *")
and vtyinfo_7189.getType().hasName("TypeInfo *")
and vfout_7189.getFunction() = func
and vtyinfo_7189.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
