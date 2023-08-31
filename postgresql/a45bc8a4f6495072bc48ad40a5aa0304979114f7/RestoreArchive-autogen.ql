/**
 * @name postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-RestoreArchive
 * @id cpp/postgresql/a45bc8a4f6495072bc48ad40a5aa0304979114f7/RestoreArchive
 * @description postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-src/bin/pg_dump/pg_backup_archiver.c-RestoreArchive CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vropt_347, IfStmt target_8, ExprStmt target_9) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Archive *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dbname"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pghost"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pgport"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="username"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="promptPassword"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_8.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vropt_347, VariableAccess target_2) {
		target_2.getTarget()=vropt_347
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Archive *")
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dbname"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pghost"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pgport"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="username"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="promptPassword"
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
}

predicate func_3(Variable vropt_347, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="dbname"
		and target_3.getQualifier().(VariableAccess).getTarget()=vropt_347
}

predicate func_4(Variable vropt_347, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="pghost"
		and target_4.getQualifier().(VariableAccess).getTarget()=vropt_347
}

predicate func_5(Variable vropt_347, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="pgport"
		and target_5.getQualifier().(VariableAccess).getTarget()=vropt_347
}

predicate func_6(Variable vropt_347, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="username"
		and target_6.getQualifier().(VariableAccess).getTarget()=vropt_347
}

predicate func_7(Variable vropt_347, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="promptPassword"
		and target_7.getQualifier().(VariableAccess).getTarget()=vropt_347
}

predicate func_8(Variable vropt_347, IfStmt target_8) {
		target_8.getCondition().(PointerFieldAccess).getTarget().getName()="useDB"
		and target_8.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_8.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_8.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_8.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pg_log_generic")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="66304"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit_nicely")
}

predicate func_9(Variable vropt_347, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Archive *")
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dbname"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_9.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pghost"
		and target_9.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pgport"
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_9.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="username"
		and target_9.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
		and target_9.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="promptPassword"
		and target_9.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_347
}

from Function func, Variable vropt_347, VariableAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, IfStmt target_8, ExprStmt target_9
where
not func_0(vropt_347, target_8, target_9)
and func_2(vropt_347, target_2)
and func_3(vropt_347, target_3)
and func_4(vropt_347, target_4)
and func_5(vropt_347, target_5)
and func_6(vropt_347, target_6)
and func_7(vropt_347, target_7)
and func_8(vropt_347, target_8)
and func_9(vropt_347, target_9)
and vropt_347.getType().hasName("RestoreOptions *")
and vropt_347.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
