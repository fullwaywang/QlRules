/**
 * @name postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-dumpOptionsFromRestoreOptions
 * @id cpp/postgresql/a45bc8a4f6495072bc48ad40a5aa0304979114f7/dumpOptionsFromRestoreOptions
 * @description postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-src/bin/pg_dump/pg_backup_archiver.c-dumpOptionsFromRestoreOptions CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vropt_176, Variable vdopt_178, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="dbname"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdopt_178
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="dbname"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="dbname"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vropt_176, Variable vdopt_178, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="pgport"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdopt_178
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="pgport"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="pgport"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vropt_176, Variable vdopt_178, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="pghost"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdopt_178
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="pghost"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="pghost"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vropt_176, Variable vdopt_178, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="username"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdopt_178
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="username"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("pg_strdup")
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="username"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_3))
}

predicate func_4(Parameter vropt_176, Variable vdopt_178, ExprStmt target_6, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="promptPassword"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdopt_178
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="promptPassword"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_4)
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vropt_176, Variable vdopt_178, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="outputClean"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdopt_178
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="dropSchema"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_176
}

from Function func, Parameter vropt_176, Variable vdopt_178, ExprStmt target_6
where
not func_0(vropt_176, vdopt_178, func)
and not func_1(vropt_176, vdopt_178, func)
and not func_2(vropt_176, vdopt_178, func)
and not func_3(vropt_176, vdopt_178, func)
and not func_4(vropt_176, vdopt_178, target_6, func)
and func_6(vropt_176, vdopt_178, target_6)
and vropt_176.getType().hasName("RestoreOptions *")
and vdopt_178.getType().hasName("DumpOptions *")
and vropt_176.getFunction() = func
and vdopt_178.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
