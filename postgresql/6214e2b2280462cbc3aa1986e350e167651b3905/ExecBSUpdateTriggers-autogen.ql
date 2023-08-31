/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecBSUpdateTriggers
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecBSUpdateTriggers
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/commands/trigger.c-ExecBSUpdateTriggers CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vupdatedCols_2632, FunctionCall target_0) {
		target_0.getTarget().hasName("bms_union")
		and not target_0.getTarget().hasName("ExecGetAllUpdatedCols")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="updatedCols"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="extraUpdatedCols"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vupdatedCols_2632
}

predicate func_2(Parameter vrelinfo_2627, Variable vupdatedCols_2632, Parameter vestate_2627, PointerFieldAccess target_7, ExprStmt target_9, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vupdatedCols_2632
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecGetAllUpdatedCols")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrelinfo_2627
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_2627
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_2)
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vestate_2627, VariableAccess target_3) {
		target_3.getTarget()=vestate_2627
		and target_3.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_4(Parameter vrelinfo_2627, VariableAccess target_4) {
		target_4.getTarget()=vrelinfo_2627
		and target_4.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_5(Parameter vrelinfo_2627, Parameter vestate_2627, PointerFieldAccess target_7, FunctionCall target_5) {
		target_5.getTarget().hasName("exec_rt_fetch")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2627
		and target_5.getArgument(1).(VariableAccess).getTarget()=vestate_2627
		and target_5.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_6(Parameter vrelinfo_2627, Parameter vestate_2627, ExprStmt target_10, NotExpr target_11, FunctionCall target_6) {
		target_6.getTarget().hasName("exec_rt_fetch")
		and target_6.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2627
		and target_6.getArgument(1).(VariableAccess).getTarget()=vestate_2627
		and target_6.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_7(Parameter vrelinfo_2627, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="rd_id"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2627
}

predicate func_9(Variable vupdatedCols_2632, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="tg_updatedcols"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TriggerData")
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vupdatedCols_2632
}

predicate func_10(Parameter vrelinfo_2627, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="tg_relation"
		and target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TriggerData")
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2627
}

predicate func_11(Parameter vrelinfo_2627, Variable vupdatedCols_2632, Parameter vestate_2627, NotExpr target_11) {
		target_11.getOperand().(FunctionCall).getTarget().hasName("TriggerEnabled")
		and target_11.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vestate_2627
		and target_11.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrelinfo_2627
		and target_11.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("Trigger *")
		and target_11.getOperand().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="tg_event"
		and target_11.getOperand().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TriggerData")
		and target_11.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vupdatedCols_2632
		and target_11.getOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_11.getOperand().(FunctionCall).getArgument(6).(Literal).getValue()="0"
}

from Function func, Parameter vrelinfo_2627, Variable vupdatedCols_2632, Parameter vestate_2627, FunctionCall target_0, VariableAccess target_3, VariableAccess target_4, FunctionCall target_5, FunctionCall target_6, PointerFieldAccess target_7, ExprStmt target_9, ExprStmt target_10, NotExpr target_11
where
func_0(vupdatedCols_2632, target_0)
and not func_2(vrelinfo_2627, vupdatedCols_2632, vestate_2627, target_7, target_9, func)
and func_3(vestate_2627, target_3)
and func_4(vrelinfo_2627, target_4)
and func_5(vrelinfo_2627, vestate_2627, target_7, target_5)
and func_6(vrelinfo_2627, vestate_2627, target_10, target_11, target_6)
and func_7(vrelinfo_2627, target_7)
and func_9(vupdatedCols_2632, target_9)
and func_10(vrelinfo_2627, target_10)
and func_11(vrelinfo_2627, vupdatedCols_2632, vestate_2627, target_11)
and vrelinfo_2627.getType().hasName("ResultRelInfo *")
and vupdatedCols_2632.getType().hasName("Bitmapset *")
and vestate_2627.getType().hasName("EState *")
and vrelinfo_2627.getFunction() = func
and vupdatedCols_2632.(LocalVariable).getFunction() = func
and vestate_2627.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
