/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecUpdateLockMode
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecUpdateLockMode
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execMain.c-ExecUpdateLockMode CVE-2021-3393
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

predicate func_1(Parameter vestate_2217, VariableAccess target_1) {
		target_1.getTarget()=vestate_2217
		and target_1.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_2(Parameter vrelinfo_2217, VariableAccess target_2) {
		target_2.getTarget()=vrelinfo_2217
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_3(Parameter vestate_2217, Parameter vrelinfo_2217, FunctionCall target_3) {
		target_3.getTarget().hasName("exec_rt_fetch")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2217
		and target_3.getArgument(1).(VariableAccess).getTarget()=vestate_2217
		and target_3.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Parameter vestate_2217, Parameter vrelinfo_2217, ExprStmt target_5, FunctionCall target_4) {
		target_4.getTarget().hasName("exec_rt_fetch")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2217
		and target_4.getArgument(1).(VariableAccess).getTarget()=vestate_2217
		and target_4.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_5(Parameter vrelinfo_2217, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Bitmapset *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelationGetIndexAttrBitmap")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelinfo_2217
}

from Function func, Parameter vestate_2217, Parameter vrelinfo_2217, FunctionCall target_0, VariableAccess target_1, VariableAccess target_2, FunctionCall target_3, FunctionCall target_4, ExprStmt target_5
where
func_0(func, target_0)
and func_1(vestate_2217, target_1)
and func_2(vrelinfo_2217, target_2)
and func_3(vestate_2217, vrelinfo_2217, target_3)
and func_4(vestate_2217, vrelinfo_2217, target_5, target_4)
and func_5(vrelinfo_2217, target_5)
and vestate_2217.getType().hasName("EState *")
and vrelinfo_2217.getType().hasName("ResultRelInfo *")
and vestate_2217.getFunction() = func
and vrelinfo_2217.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
