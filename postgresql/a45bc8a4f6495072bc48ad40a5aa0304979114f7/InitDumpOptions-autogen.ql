/**
 * @name postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-InitDumpOptions
 * @id cpp/postgresql/a45bc8a4f6495072bc48ad40a5aa0304979114f7/InitDumpOptions
 * @description postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-src/bin/pg_dump/pg_backup_archiver.c-InitDumpOptions CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="160"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vopts_163, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="promptPassword"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopts_163
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_1)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vopts_163, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="include_everything"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopts_163
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_3(Parameter vopts_163, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dumpSections"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopts_163
}

from Function func, Parameter vopts_163, SizeofTypeOperator target_0, ExprStmt target_2, ExprStmt target_3
where
func_0(func, target_0)
and not func_1(vopts_163, target_2, target_3, func)
and func_2(vopts_163, target_2)
and func_3(vopts_163, target_3)
and vopts_163.getType().hasName("DumpOptions *")
and vopts_163.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
