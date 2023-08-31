/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-_doSetFixedOutputState
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/-doSetFixedOutputState
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_backup_archiver.c-_doSetFixedOutputState CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vAH_3097, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ValueFieldAccess).getTarget().getName()="searchpath"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="public"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_3097
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_3097
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="searchpath"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="public"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_3097
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vAH_3097, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_3097
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SET ROLE %s;\n"
		and target_1.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("fmtId")
		and target_1.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="use_role"
		and target_1.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("RestoreOptions *")
}

predicate func_2(Parameter vAH_3097, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_3097
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SET check_function_bodies = false;\n"
}

from Function func, Parameter vAH_3097, ExprStmt target_1, ExprStmt target_2
where
not func_0(vAH_3097, target_1, target_2, func)
and func_1(vAH_3097, target_1)
and func_2(vAH_3097, target_2)
and vAH_3097.getType().hasName("ArchiveHandle *")
and vAH_3097.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
