/**
 * @name postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-restore_toc_entries_postfork
 * @id cpp/postgresql/a45bc8a4f6495072bc48ad40a5aa0304979114f7/restore-toc-entries-postfork
 * @description postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-src/bin/pg_dump/pg_backup_archiver.c-restore_toc_entries_postfork CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vropt_4154, ExprStmt target_9) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dbname"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pghost"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pgport"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="username"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="promptPassword"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vropt_4154, VariableAccess target_2) {
		target_2.getTarget()=vropt_4154
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dbname"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pghost"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pgport"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="username"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="promptPassword"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
}

predicate func_3(Variable vropt_4154, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="dbname"
		and target_3.getQualifier().(VariableAccess).getTarget()=vropt_4154
}

predicate func_4(Variable vropt_4154, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="pghost"
		and target_4.getQualifier().(VariableAccess).getTarget()=vropt_4154
}

predicate func_5(Variable vropt_4154, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="pgport"
		and target_5.getQualifier().(VariableAccess).getTarget()=vropt_4154
}

predicate func_6(Variable vropt_4154, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="username"
		and target_6.getQualifier().(VariableAccess).getTarget()=vropt_4154
}

predicate func_7(Variable vropt_4154, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="promptPassword"
		and target_7.getQualifier().(VariableAccess).getTarget()=vropt_4154
}

predicate func_9(Variable vropt_4154, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dbname"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_9.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pghost"
		and target_9.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pgport"
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_9.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="username"
		and target_9.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
		and target_9.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="promptPassword"
		and target_9.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_4154
}

from Function func, Variable vropt_4154, VariableAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, ExprStmt target_9
where
not func_0(vropt_4154, target_9)
and func_2(vropt_4154, target_2)
and func_3(vropt_4154, target_3)
and func_4(vropt_4154, target_4)
and func_5(vropt_4154, target_5)
and func_6(vropt_4154, target_6)
and func_7(vropt_4154, target_7)
and func_9(vropt_4154, target_9)
and vropt_4154.getType().hasName("RestoreOptions *")
and vropt_4154.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
