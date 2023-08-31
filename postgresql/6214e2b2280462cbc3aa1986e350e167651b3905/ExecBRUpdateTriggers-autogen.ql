/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecBRUpdateTriggers
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecBRUpdateTriggers
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/commands/trigger.c-ExecBRUpdateTriggers CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("bms_union")
		and not target_0.getTarget().hasName("ExecGetAllUpdatedCols")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="updatedCols"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="extraUpdatedCols"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Bitmapset *")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vestate_2695, VariableAccess target_1) {
		target_1.getTarget()=vestate_2695
		and target_1.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_2(Parameter vrelinfo_2696, VariableAccess target_2) {
		target_2.getTarget()=vrelinfo_2696
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_3(Parameter vestate_2695, Parameter vrelinfo_2696, NotExpr target_5, ExprStmt target_6, FunctionCall target_3) {
		target_3.getTarget().hasName("exec_rt_fetch")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2696
		and target_3.getArgument(1).(VariableAccess).getTarget()=vestate_2695
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Parameter vestate_2695, Parameter vrelinfo_2696, NotExpr target_7, FunctionCall target_4) {
		target_4.getTarget().hasName("exec_rt_fetch")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2696
		and target_4.getArgument(1).(VariableAccess).getTarget()=vestate_2695
		and target_4.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_4.getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_5(Parameter vestate_2695, Parameter vrelinfo_2696, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("GetTupleForTrigger")
		and target_5.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vestate_2695
		and target_5.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("EPQState *")
		and target_5.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrelinfo_2696
		and target_5.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("ItemPointer")
		and target_5.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("LockTupleMode")
		and target_5.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_5.getOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_6(Parameter vrelinfo_2696, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="tg_relation"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TriggerData")
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2696
}

predicate func_7(Parameter vestate_2695, Parameter vrelinfo_2696, NotExpr target_7) {
		target_7.getOperand().(FunctionCall).getTarget().hasName("TriggerEnabled")
		and target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vestate_2695
		and target_7.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrelinfo_2696
		and target_7.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("Trigger *")
		and target_7.getOperand().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="tg_event"
		and target_7.getOperand().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TriggerData")
		and target_7.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("Bitmapset *")
		and target_7.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_7.getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

from Function func, Parameter vestate_2695, Parameter vrelinfo_2696, FunctionCall target_0, VariableAccess target_1, VariableAccess target_2, FunctionCall target_3, FunctionCall target_4, NotExpr target_5, ExprStmt target_6, NotExpr target_7
where
func_0(func, target_0)
and func_1(vestate_2695, target_1)
and func_2(vrelinfo_2696, target_2)
and func_3(vestate_2695, vrelinfo_2696, target_5, target_6, target_3)
and func_4(vestate_2695, vrelinfo_2696, target_7, target_4)
and func_5(vestate_2695, vrelinfo_2696, target_5)
and func_6(vrelinfo_2696, target_6)
and func_7(vestate_2695, vrelinfo_2696, target_7)
and vestate_2695.getType().hasName("EState *")
and vrelinfo_2696.getType().hasName("ResultRelInfo *")
and vestate_2695.getFunction() = func
and vrelinfo_2696.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
