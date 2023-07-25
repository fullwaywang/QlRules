/**
 * @name postgresql-a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3-ExecDelete
 * @id cpp/postgresql/a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3/ExecDelete
 * @description postgresql-a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3-src/backend/executor/nodeModifyTable.c-ExecDelete CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresultRelInfo_721, ExprStmt target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="ri_projectReturning"
		and target_0.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_721
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vresultRelationDesc_722, NotExpr target_4) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="rd_id"
		and target_1.getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_722
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vresultRelInfo_721, VariableAccess target_2) {
		target_2.getTarget()=vresultRelInfo_721
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_3(Variable vresultRelInfo_721, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecGetReturningSlot")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("EState *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_721
}

predicate func_4(Variable vresultRelationDesc_722, NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("table_tuple_fetch_row_version")
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelationDesc_722
		and target_4.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("ItemPointer")
		and target_4.getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("SnapshotData")
		and target_4.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

from Function func, Variable vresultRelInfo_721, Variable vresultRelationDesc_722, VariableAccess target_2, ExprStmt target_3, NotExpr target_4
where
not func_0(vresultRelInfo_721, target_3)
and not func_1(vresultRelationDesc_722, target_4)
and func_2(vresultRelInfo_721, target_2)
and func_3(vresultRelInfo_721, target_3)
and func_4(vresultRelationDesc_722, target_4)
and vresultRelInfo_721.getType().hasName("ResultRelInfo *")
and vresultRelationDesc_722.getType().hasName("Relation")
and vresultRelInfo_721.(LocalVariable).getFunction() = func
and vresultRelationDesc_722.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
