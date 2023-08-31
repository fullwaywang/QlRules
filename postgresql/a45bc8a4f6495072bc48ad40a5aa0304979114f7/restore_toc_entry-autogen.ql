/**
 * @name postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-restore_toc_entry
 * @id cpp/postgresql/a45bc8a4f6495072bc48ad40a5aa0304979114f7/restore-toc-entry
 * @description postgresql-a45bc8a4f6495072bc48ad40a5aa0304979114f7-src/bin/pg_dump/pg_backup_archiver.c-restore_toc_entry CVE-2020-25694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(LogicalOrExpr target_5, Function func, DeclStmt target_0) {
		target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vconnstr_835, LogicalOrExpr target_5, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_835
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_2(Variable vconnstr_835, LogicalOrExpr target_5, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_835
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname="
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_3(Parameter vte_752, Variable vconnstr_835, LogicalOrExpr target_5, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconnstr_835
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tag"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_752
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_4(Variable vropt_754, Variable vconnstr_835, LogicalOrExpr target_5, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dbname"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_754
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnstr_835
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_5(Parameter vte_752, LogicalOrExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="desc"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_752
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DATABASE"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="desc"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_752
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DATABASE PROPERTIES"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vte_752, Variable vropt_754, Variable vconnstr_835, DeclStmt target_0, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, LogicalOrExpr target_5
where
func_0(target_5, func, target_0)
and func_1(vconnstr_835, target_5, target_1)
and func_2(vconnstr_835, target_5, target_2)
and func_3(vte_752, vconnstr_835, target_5, target_3)
and func_4(vropt_754, vconnstr_835, target_5, target_4)
and func_5(vte_752, target_5)
and vte_752.getType().hasName("TocEntry *")
and vropt_754.getType().hasName("RestoreOptions *")
and vconnstr_835.getType().hasName("PQExpBufferData")
and vte_752.getFunction() = func
and vropt_754.(LocalVariable).getFunction() = func
and vconnstr_835.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
