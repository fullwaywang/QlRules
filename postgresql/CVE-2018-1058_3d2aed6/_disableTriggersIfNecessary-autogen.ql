/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-_disableTriggersIfNecessary
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/-disableTriggersIfNecessary
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_backup_archiver.c-_disableTriggersIfNecessary CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vAH_969, Parameter vte_969, FunctionCall target_0) {
		target_0.getTarget().hasName("fmtId")
		and not target_0.getTarget().hasName("fmtQualifiedId")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="tag"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_969
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_969
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ALTER TABLE %s DISABLE TRIGGER ALL;\n\n"
}

predicate func_1(Parameter vAH_969) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("PQserverVersion")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_969
		and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2) instanceof FunctionCall)
}

predicate func_2(Parameter vte_969, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="namespace"
		and target_2.getQualifier().(VariableAccess).getTarget()=vte_969
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Parameter vAH_969, VariableAccess target_3) {
		target_3.getTarget()=vAH_969
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Parameter vAH_969, VariableAccess target_4) {
		target_4.getTarget()=vAH_969
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ALTER TABLE %s DISABLE TRIGGER ALL;\n\n"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
}

predicate func_5(Parameter vAH_969, Parameter vte_969, FunctionCall target_5) {
		target_5.getTarget().hasName("_selectOutputSchema")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vAH_969
		and target_5.getArgument(1).(PointerFieldAccess).getTarget().getName()="namespace"
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_969
}

predicate func_6(Parameter vAH_969, Function func, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_969
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ALTER TABLE %s DISABLE TRIGGER ALL;\n\n"
		and target_6.getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

from Function func, Parameter vAH_969, Parameter vte_969, FunctionCall target_0, PointerFieldAccess target_2, VariableAccess target_3, VariableAccess target_4, FunctionCall target_5, ExprStmt target_6
where
func_0(vAH_969, vte_969, target_0)
and not func_1(vAH_969)
and func_2(vte_969, target_2)
and func_3(vAH_969, target_3)
and func_4(vAH_969, target_4)
and func_5(vAH_969, vte_969, target_5)
and func_6(vAH_969, func, target_6)
and vAH_969.getType().hasName("ArchiveHandle *")
and vte_969.getType().hasName("TocEntry *")
and vAH_969.getFunction() = func
and vte_969.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
