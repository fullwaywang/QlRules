/**
 * @name postgresql-a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3-ExecUpdate
 * @id cpp/postgresql/a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3/ExecUpdate
 * @description postgresql-a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3-src/backend/executor/nodeModifyTable.c-ExecUpdate CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vresultRelInfo_1078, IfStmt target_4, FunctionCall target_5) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="ri_projectReturning"
		and target_1.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1078
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vresultRelationDesc_1079, ExprStmt target_6) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="rd_id"
		and target_2.getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_1079
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vresultRelInfo_1078, VariableAccess target_3) {
		target_3.getTarget()=vresultRelInfo_1078
		and target_3.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_3.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_3.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_4(Variable vresultRelInfo_1078, IfStmt target_4) {
		target_4.getCondition().(PointerFieldAccess).getTarget().getName()="ri_projectReturning"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1078
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_1078
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_4.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_5(Variable vresultRelInfo_1078, FunctionCall target_5) {
		target_5.getTarget().hasName("ExecProcessReturning")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_1078
		and target_5.getArgument(1).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_5.getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_6(Variable vresultRelInfo_1078, Variable vresultRelationDesc_1079, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("EvalPlanQual")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("EPQState *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vresultRelationDesc_1079
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1078
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

from Function func, Variable vresultRelInfo_1078, Variable vresultRelationDesc_1079, VariableAccess target_3, IfStmt target_4, FunctionCall target_5, ExprStmt target_6
where
not func_1(vresultRelInfo_1078, target_4, target_5)
and not func_2(vresultRelationDesc_1079, target_6)
and func_3(vresultRelInfo_1078, target_3)
and func_4(vresultRelInfo_1078, target_4)
and func_5(vresultRelInfo_1078, target_5)
and func_6(vresultRelInfo_1078, vresultRelationDesc_1079, target_6)
and vresultRelInfo_1078.getType().hasName("ResultRelInfo *")
and vresultRelationDesc_1079.getType().hasName("Relation")
and vresultRelInfo_1078.(LocalVariable).getFunction() = func
and vresultRelationDesc_1079.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
