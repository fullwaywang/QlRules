/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-CloneArchive
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/CloneArchive
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_dump/pg_backup_archiver.c-CloneArchive CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("initPQExpBuffer")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("appendPQExpBuffer")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getArgument(1).(StringLiteral).getValue()="dbname="
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(EqualityOperation target_11, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getExpr().(FunctionCall).getArgument(1) instanceof FunctionCall
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(7)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vclone_4420, Variable vpghost_4467, Variable vpgport_4468, Variable vusername_4469, EqualityOperation target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclone_4420
		and target_4.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpghost_4467
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpgport_4468
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vusername_4469
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(11)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

/*predicate func_5(Function func) {
	exists(ValueFieldAccess target_5 |
		target_5.getTarget().getName()="data"
		and target_5.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getEnclosingFunction() = func)
}

*/
predicate func_6(EqualityOperation target_11, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(12)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vAH_4418, Variable vdbname_4466, FunctionCall target_7) {
		target_7.getTarget().hasName("PQdb")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_4418
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdbname_4466
}

predicate func_9(Variable vdbname_4466, AssignExpr target_9) {
		target_9.getLValue().(VariableAccess).getTarget()=vdbname_4466
		and target_9.getRValue() instanceof FunctionCall
}

predicate func_10(Variable vclone_4420, Variable vdbname_4466, Variable vpghost_4467, Variable vpgport_4468, Variable vusername_4469, VariableAccess target_10) {
		target_10.getTarget()=vdbname_4466
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ConnectDatabase")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclone_4420
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpghost_4467
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpgport_4468
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vusername_4469
}

predicate func_11(Parameter vAH_4418, EqualityOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_4418
}

predicate func_12(Variable vclone_4420, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("_doSetFixedOutputState")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclone_4420
}

predicate func_13(Variable vclone_4420, ExprStmt target_13) {
		target_13.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="ClonePtr"
		and target_13.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_4420
		and target_13.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vclone_4420
}

predicate func_14(Parameter vAH_4418, Variable vpghost_4467, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpghost_4467
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQhost")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_4418
}

predicate func_15(Parameter vAH_4418, Variable vpgport_4468, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpgport_4468
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQport")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_4418
}

predicate func_16(Parameter vAH_4418, Variable vusername_4469, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vusername_4469
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQuser")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="connection"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_4418
}

from Function func, Parameter vAH_4418, Variable vclone_4420, Variable vdbname_4466, Variable vpghost_4467, Variable vpgport_4468, Variable vusername_4469, FunctionCall target_7, AssignExpr target_9, VariableAccess target_10, EqualityOperation target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16
where
not func_1(func)
and not func_2(func)
and not func_3(target_11, func)
and not func_4(vclone_4420, vpghost_4467, vpgport_4468, vusername_4469, target_11, target_12, target_13, target_14, target_15, target_16)
and not func_6(target_11, func)
and func_7(vAH_4418, vdbname_4466, target_7)
and func_9(vdbname_4466, target_9)
and func_10(vclone_4420, vdbname_4466, vpghost_4467, vpgport_4468, vusername_4469, target_10)
and func_11(vAH_4418, target_11)
and func_12(vclone_4420, target_12)
and func_13(vclone_4420, target_13)
and func_14(vAH_4418, vpghost_4467, target_14)
and func_15(vAH_4418, vpgport_4468, target_15)
and func_16(vAH_4418, vusername_4469, target_16)
and vAH_4418.getType().hasName("ArchiveHandle *")
and vclone_4420.getType().hasName("ArchiveHandle *")
and vdbname_4466.getType().hasName("char *")
and vpghost_4467.getType().hasName("char *")
and vpgport_4468.getType().hasName("char *")
and vusername_4469.getType().hasName("char *")
and vAH_4418.getFunction() = func
and vclone_4420.(LocalVariable).getFunction() = func
and vdbname_4466.(LocalVariable).getFunction() = func
and vpghost_4467.(LocalVariable).getFunction() = func
and vpgport_4468.(LocalVariable).getFunction() = func
and vusername_4469.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
