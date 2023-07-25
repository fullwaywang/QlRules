/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-_selectOutputSchema
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/-selectOutputSchema
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_backup_archiver.c-_selectOutputSchema CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vAH_3320, LogicalOrExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ValueFieldAccess).getTarget().getName()="searchpath"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="public"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_3320
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vAH_3320, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="currSchema"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_3320
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="currSchema"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_3320
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vAH_3320, LogicalOrExpr target_1
where
not func_0(vAH_3320, target_1, func)
and func_1(vAH_3320, target_1)
and vAH_3320.getType().hasName("ArchiveHandle *")
and vAH_3320.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
