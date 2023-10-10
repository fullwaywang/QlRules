/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-index_unchanged_by_update
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/index-unchanged-by-update
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execIndexing.c-index_unchanged_by_update CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vresultRelInfo_944, Parameter vestate_944, FunctionCall target_8) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ExecGetUpdatedCols")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_944
		and target_0.getArgument(1).(VariableAccess).getTarget()=vestate_944
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vresultRelInfo_944, Parameter vestate_944, FunctionCall target_9) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("ExecGetExtraUpdatedCols")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_944
		and target_1.getArgument(1).(VariableAccess).getTarget()=vestate_944
		and target_9.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vestate_944, VariableAccess target_2) {
		target_2.getTarget()=vestate_944
		and target_2.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_3(Parameter vestate_944, VariableAccess target_3) {
		target_3.getTarget()=vestate_944
		and target_3.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_4(Parameter vresultRelInfo_944, VariableAccess target_4) {
		target_4.getTarget()=vresultRelInfo_944
		and target_4.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_5(Parameter vresultRelInfo_944, VariableAccess target_5) {
		target_5.getTarget()=vresultRelInfo_944
		and target_5.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_6(Parameter vresultRelInfo_944, Parameter vestate_944, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="updatedCols"
		and target_6.getQualifier().(FunctionCall).getTarget().hasName("exec_rt_fetch")
		and target_6.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_6.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_944
		and target_6.getQualifier().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_944
}

predicate func_7(Parameter vresultRelInfo_944, Parameter vestate_944, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="extraUpdatedCols"
		and target_7.getQualifier().(FunctionCall).getTarget().hasName("exec_rt_fetch")
		and target_7.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_7.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_944
		and target_7.getQualifier().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_944
}

predicate func_8(Parameter vresultRelInfo_944, Parameter vestate_944, FunctionCall target_8) {
		target_8.getTarget().hasName("exec_rt_fetch")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_944
		and target_8.getArgument(1).(VariableAccess).getTarget()=vestate_944
}

predicate func_9(Parameter vresultRelInfo_944, Parameter vestate_944, FunctionCall target_9) {
		target_9.getTarget().hasName("exec_rt_fetch")
		and target_9.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_9.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_944
		and target_9.getArgument(1).(VariableAccess).getTarget()=vestate_944
}

from Function func, Parameter vresultRelInfo_944, Parameter vestate_944, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, FunctionCall target_8, FunctionCall target_9
where
not func_0(vresultRelInfo_944, vestate_944, target_8)
and not func_1(vresultRelInfo_944, vestate_944, target_9)
and func_2(vestate_944, target_2)
and func_3(vestate_944, target_3)
and func_4(vresultRelInfo_944, target_4)
and func_5(vresultRelInfo_944, target_5)
and func_6(vresultRelInfo_944, vestate_944, target_6)
and func_7(vresultRelInfo_944, vestate_944, target_7)
and func_8(vresultRelInfo_944, vestate_944, target_8)
and func_9(vresultRelInfo_944, vestate_944, target_9)
and vresultRelInfo_944.getType().hasName("ResultRelInfo *")
and vestate_944.getType().hasName("EState *")
and vresultRelInfo_944.getFunction() = func
and vestate_944.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
