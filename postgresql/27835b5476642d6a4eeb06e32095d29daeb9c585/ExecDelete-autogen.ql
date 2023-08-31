/**
 * @name postgresql-27835b5476642d6a4eeb06e32095d29daeb9c585-ExecDelete
 * @id cpp/postgresql/27835b5476642d6a4eeb06e32095d29daeb9c585/ExecDelete
 * @description postgresql-27835b5476642d6a4eeb06e32095d29daeb9c585-src/backend/executor/nodeModifyTable.c-ExecDelete CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresultRelInfo_634, IfStmt target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="ri_projectReturning"
		and target_0.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_634
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vresultRelationDesc_635, ExprStmt target_4) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="rd_id"
		and target_1.getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_635
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vresultRelInfo_634, VariableAccess target_2) {
		target_2.getTarget()=vresultRelInfo_634
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_3(Variable vresultRelInfo_634, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="ri_FdwRoutine"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_634
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Buffer")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="es_trig_tuple_slot"
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EState *")
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("HeapTuple")
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("HeapTupleData")
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Buffer")
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="t_self"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("heap_fetch")
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
}

predicate func_4(Variable vresultRelationDesc_635, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ExecSetSlotDescriptor")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_635
}

from Function func, Variable vresultRelInfo_634, Variable vresultRelationDesc_635, VariableAccess target_2, IfStmt target_3, ExprStmt target_4
where
not func_0(vresultRelInfo_634, target_3)
and not func_1(vresultRelationDesc_635, target_4)
and func_2(vresultRelInfo_634, target_2)
and func_3(vresultRelInfo_634, target_3)
and func_4(vresultRelationDesc_635, target_4)
and vresultRelInfo_634.getType().hasName("ResultRelInfo *")
and vresultRelationDesc_635.getType().hasName("Relation")
and vresultRelInfo_634.(LocalVariable).getFunction() = func
and vresultRelationDesc_635.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
