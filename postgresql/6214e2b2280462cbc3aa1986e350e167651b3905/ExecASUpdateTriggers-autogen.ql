/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecASUpdateTriggers
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecASUpdateTriggers
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/commands/trigger.c-ExecASUpdateTriggers CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrelinfo_2682, Parameter vestate_2682, FunctionCall target_0) {
		target_0.getTarget().hasName("bms_union")
		and not target_0.getTarget().hasName("ExecGetAllUpdatedCols")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="updatedCols"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="extraUpdatedCols"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("AfterTriggerSaveEvent")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vestate_2682
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrelinfo_2682
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("TransitionCaptureState *")
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vestate_2682, VariableAccess target_2) {
		target_2.getTarget()=vestate_2682
		and target_2.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_3(Parameter vrelinfo_2682, VariableAccess target_3) {
		target_3.getTarget()=vrelinfo_2682
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_4(Parameter vrelinfo_2682, Parameter vestate_2682, ExprStmt target_6, FunctionCall target_4) {
		target_4.getTarget().hasName("exec_rt_fetch")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2682
		and target_4.getArgument(1).(VariableAccess).getTarget()=vestate_2682
		and target_4.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(FunctionCall).getArgument(7) instanceof FunctionCall
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_5(Parameter vrelinfo_2682, Parameter vestate_2682, FunctionCall target_5) {
		target_5.getTarget().hasName("exec_rt_fetch")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2682
		and target_5.getArgument(1).(VariableAccess).getTarget()=vestate_2682
		and target_5.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(FunctionCall).getArgument(7) instanceof FunctionCall
}

predicate func_6(Parameter vrelinfo_2682, Parameter vestate_2682, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("AfterTriggerSaveEvent")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vestate_2682
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrelinfo_2682
		and target_6.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_6.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(7) instanceof FunctionCall
		and target_6.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("TransitionCaptureState *")
}

from Function func, Parameter vrelinfo_2682, Parameter vestate_2682, FunctionCall target_0, VariableAccess target_2, VariableAccess target_3, FunctionCall target_4, FunctionCall target_5, ExprStmt target_6
where
func_0(vrelinfo_2682, vestate_2682, target_0)
and not func_1(func)
and func_2(vestate_2682, target_2)
and func_3(vrelinfo_2682, target_3)
and func_4(vrelinfo_2682, vestate_2682, target_6, target_4)
and func_5(vrelinfo_2682, vestate_2682, target_5)
and func_6(vrelinfo_2682, vestate_2682, target_6)
and vrelinfo_2682.getType().hasName("ResultRelInfo *")
and vestate_2682.getType().hasName("EState *")
and vrelinfo_2682.getFunction() = func
and vestate_2682.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
