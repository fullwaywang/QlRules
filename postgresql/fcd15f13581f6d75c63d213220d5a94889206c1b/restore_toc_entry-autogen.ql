/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-restore_toc_entry
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/restore-toc-entry
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_dump/pg_backup_archiver.c-restore_toc_entry CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("initPQExpBuffer")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(EqualityOperation target_7, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname="
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vte_688, EqualityOperation target_7, ExprStmt target_8, IfStmt target_9) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tag"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_688
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vropt_690, EqualityOperation target_7, IfStmt target_10) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dbname"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_690
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_10.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_4(Function func) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="data"
		and target_4.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_5(Parameter vte_688, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="tag"
		and target_5.getQualifier().(VariableAccess).getTarget()=vte_688
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_6(Parameter vte_688, Variable vropt_690, FunctionCall target_6) {
		target_6.getTarget().hasName("pg_strdup")
		and target_6.getArgument(0).(PointerFieldAccess).getTarget().getName()="tag"
		and target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_688
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dbname"
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_690
}

predicate func_7(Parameter vte_688, EqualityOperation target_7) {
		target_7.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_7.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="desc"
		and target_7.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_688
		and target_7.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DATABASE"
		and target_7.getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Parameter vte_688, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("_reconnectToDB")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tag"
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_688
}

predicate func_9(Parameter vte_688, IfStmt target_9) {
		target_9.getCondition().(PointerFieldAccess).getTarget().getName()="hadDumper"
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_688
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="PrintTocDataPtr"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_printTocEntry")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vte_688
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_9.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ahlog")
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="executing %s %s\n"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="desc"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_688
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="tag"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_688
}

predicate func_10(Parameter vte_688, Variable vropt_690, IfStmt target_10) {
		target_10.getCondition().(PointerFieldAccess).getTarget().getName()="noDataForFailedTables"
		and target_10.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vropt_690
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget().getType().hasName("bool")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="11"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("inhibit_data_for_failed_table")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ArchiveHandle *")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vte_688
}

from Function func, Parameter vte_688, Variable vropt_690, PointerFieldAccess target_5, FunctionCall target_6, EqualityOperation target_7, ExprStmt target_8, IfStmt target_9, IfStmt target_10
where
not func_0(func)
and not func_1(target_7, func)
and not func_2(vte_688, target_7, target_8, target_9)
and not func_3(vropt_690, target_7, target_10)
and func_5(vte_688, target_5)
and func_6(vte_688, vropt_690, target_6)
and func_7(vte_688, target_7)
and func_8(vte_688, target_8)
and func_9(vte_688, target_9)
and func_10(vte_688, vropt_690, target_10)
and vte_688.getType().hasName("TocEntry *")
and vropt_690.getType().hasName("RestoreOptions *")
and vte_688.getFunction() = func
and vropt_690.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
