/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-restore_toc_entry
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/restore-toc-entry
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_backup_archiver.c-restore_toc_entry CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vAH_739, Parameter vte_739, FunctionCall target_0) {
		target_0.getTarget().hasName("fmtId")
		and not target_0.getTarget().hasName("fmtQualifiedId")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="tag"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_739
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_739
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="TRUNCATE TABLE %s%s;\n\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("PQserverVersion")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_739
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="80400"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(StringLiteral).getValue()="ONLY "
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
}

predicate func_1(Parameter vAH_739, ConditionalExpr target_3, ExprStmt target_4) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("PQserverVersion")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_739
		and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(3) instanceof FunctionCall
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vte_739, LogicalAndExpr target_5, FunctionCall target_0) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="namespace"
		and target_2.getQualifier().(VariableAccess).getTarget()=vte_739
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vAH_739, ConditionalExpr target_3) {
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("PQserverVersion")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_739
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="80400"
		and target_3.getThen().(StringLiteral).getValue()="ONLY "
		and target_3.getElse().(StringLiteral).getValue()=""
}

predicate func_4(Parameter vAH_739, Parameter vte_739, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ahprintf")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_739
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="copyStmt"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_739
}

predicate func_5(Parameter vte_739, LogicalAndExpr target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="created"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_739
}

from Function func, Parameter vAH_739, Parameter vte_739, FunctionCall target_0, ConditionalExpr target_3, ExprStmt target_4, LogicalAndExpr target_5
where
func_0(vAH_739, vte_739, target_0)
and not func_1(vAH_739, target_3, target_4)
and not func_2(vte_739, target_5, target_0)
and func_3(vAH_739, target_3)
and func_4(vAH_739, vte_739, target_4)
and func_5(vte_739, target_5)
and vAH_739.getType().hasName("ArchiveHandle *")
and vte_739.getType().hasName("TocEntry *")
and vAH_739.getFunction() = func
and vte_739.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
