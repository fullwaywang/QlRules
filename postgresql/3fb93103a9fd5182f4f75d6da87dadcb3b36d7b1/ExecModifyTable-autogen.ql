/**
 * @name postgresql-3fb93103a9fd5182f4f75d6da87dadcb3b36d7b1-ExecModifyTable
 * @id cpp/postgresql/3fb93103a9fd5182f4f75d6da87dadcb3b36d7b1/ExecModifyTable
 * @description postgresql-3fb93103a9fd5182f4f75d6da87dadcb3b36d7b1-src/backend/executor/nodeModifyTable.c-ExecModifyTable CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresultRelInfo_1999, PointerFieldAccess target_5) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="ri_projectReturning"
		and target_0.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1999
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vresultRelInfo_1999, IfStmt target_6, ExprStmt target_7) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="rd_id"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1999
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vestate_1996, ExprStmt target_8, ExprStmt target_9) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="es_result_relation_info"
		and target_3.getQualifier().(VariableAccess).getTarget()=vestate_1996
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation())
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_4(Variable vresultRelInfo_1999, VariableAccess target_4) {
		target_4.getTarget()=vresultRelInfo_1999
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_5(Variable vresultRelInfo_1999, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="rd_rel"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1999
}

predicate func_6(Variable vresultRelInfo_1999, IfStmt target_6) {
		target_6.getCondition().(PointerFieldAccess).getTarget().getName()="ri_usesFdwDirectModify"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1999
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_1999
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_7(Variable vresultRelInfo_1999, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_1999
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_8(Variable vestate_1996, Variable vresultRelInfo_1999, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecPrepareTupleRouting")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ModifyTableState *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_1996
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("PartitionTupleRouting *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vresultRelInfo_1999
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_9(Variable vestate_1996, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInsert")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ModifyTableState *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vestate_1996
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="canSetTag"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ModifyTableState *")
}

from Function func, Variable vestate_1996, Variable vresultRelInfo_1999, VariableAccess target_4, PointerFieldAccess target_5, IfStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vresultRelInfo_1999, target_5)
and not func_1(vresultRelInfo_1999, target_6, target_7)
and not func_3(vestate_1996, target_8, target_9)
and func_4(vresultRelInfo_1999, target_4)
and func_5(vresultRelInfo_1999, target_5)
and func_6(vresultRelInfo_1999, target_6)
and func_7(vresultRelInfo_1999, target_7)
and func_8(vestate_1996, vresultRelInfo_1999, target_8)
and func_9(vestate_1996, target_9)
and vestate_1996.getType().hasName("EState *")
and vresultRelInfo_1999.getType().hasName("ResultRelInfo *")
and vestate_1996.(LocalVariable).getFunction() = func
and vresultRelInfo_1999.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()