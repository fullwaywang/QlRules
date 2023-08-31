/**
 * @name postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-NewRestoreOptions
 * @id cpp/postgresql/a45bc8a4f6495072bc48ad40a5aa0304979114f7/NewRestoreOptions
 * @description postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-src/bin/pg_dump/pg_backup_archiver.c-NewRestoreOptions CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="360"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vopts_970, ExprStmt target_4, ExprStmt target_5) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="promptPassword"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="cparams"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopts_970
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vopts_970, VariableAccess target_2) {
		target_2.getTarget()=vopts_970
}

predicate func_3(Variable vopts_970, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="promptPassword"
		and target_3.getQualifier().(VariableAccess).getTarget()=vopts_970
}

predicate func_4(Variable vopts_970, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="format"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopts_970
}

predicate func_5(Variable vopts_970, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dumpSections"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopts_970
}

from Function func, Variable vopts_970, SizeofTypeOperator target_0, VariableAccess target_2, PointerFieldAccess target_3, ExprStmt target_4, ExprStmt target_5
where
func_0(func, target_0)
and not func_1(vopts_970, target_4, target_5)
and func_2(vopts_970, target_2)
and func_3(vopts_970, target_3)
and func_4(vopts_970, target_4)
and func_5(vopts_970, target_5)
and vopts_970.getType().hasName("RestoreOptions *")
and vopts_970.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
