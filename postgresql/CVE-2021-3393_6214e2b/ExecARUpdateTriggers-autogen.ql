/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecARUpdateTriggers
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecARUpdateTriggers
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/commands/trigger.c-ExecARUpdateTriggers CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vestate_2825, Parameter vrelinfo_2825, FunctionCall target_0) {
		target_0.getTarget().hasName("bms_union")
		and not target_0.getTarget().hasName("ExecGetAllUpdatedCols")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="updatedCols"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="extraUpdatedCols"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("AfterTriggerSaveEvent")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vestate_2825
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrelinfo_2825
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("List *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("TransitionCaptureState *")
}

predicate func_1(Parameter vestate_2825, VariableAccess target_1) {
		target_1.getTarget()=vestate_2825
		and target_1.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_2(Parameter vrelinfo_2825, VariableAccess target_2) {
		target_2.getTarget()=vrelinfo_2825
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_3(Parameter vestate_2825, Parameter vrelinfo_2825, ExprStmt target_5, FunctionCall target_3) {
		target_3.getTarget().hasName("exec_rt_fetch")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2825
		and target_3.getArgument(1).(VariableAccess).getTarget()=vestate_2825
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(FunctionCall).getArgument(7) instanceof FunctionCall
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(VariableAccess).getLocation())
}

predicate func_4(Parameter vestate_2825, Parameter vrelinfo_2825, FunctionCall target_4) {
		target_4.getTarget().hasName("exec_rt_fetch")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2825
		and target_4.getArgument(1).(VariableAccess).getTarget()=vestate_2825
		and target_4.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(FunctionCall).getArgument(7) instanceof FunctionCall
}

predicate func_5(Parameter vestate_2825, Parameter vrelinfo_2825, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("AfterTriggerSaveEvent")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vestate_2825
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrelinfo_2825
		and target_5.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_5.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_5.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("List *")
		and target_5.getExpr().(FunctionCall).getArgument(7) instanceof FunctionCall
		and target_5.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("TransitionCaptureState *")
}

from Function func, Parameter vestate_2825, Parameter vrelinfo_2825, FunctionCall target_0, VariableAccess target_1, VariableAccess target_2, FunctionCall target_3, FunctionCall target_4, ExprStmt target_5
where
func_0(vestate_2825, vrelinfo_2825, target_0)
and func_1(vestate_2825, target_1)
and func_2(vrelinfo_2825, target_2)
and func_3(vestate_2825, vrelinfo_2825, target_5, target_3)
and func_4(vestate_2825, vrelinfo_2825, target_4)
and func_5(vestate_2825, vrelinfo_2825, target_5)
and vestate_2825.getType().hasName("EState *")
and vrelinfo_2825.getType().hasName("ResultRelInfo *")
and vestate_2825.getFunction() = func
and vrelinfo_2825.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
