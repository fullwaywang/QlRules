/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecPartitionCheckEmitError
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecPartitionCheckEmitError
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execMain.c-ExecPartitionCheckEmitError CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vresultRelInfo_1732, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="ri_PartitionRoot"
		and target_0.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
}

predicate func_1(Parameter vresultRelInfo_1732, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="ri_PartitionRoot"
		and target_1.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
}

predicate func_2(Parameter vresultRelInfo_1732, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="ri_PartitionRoot"
		and target_2.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
}

predicate func_3(Parameter vresultRelInfo_1732, FunctionCall target_13) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="ri_RootResultRelInfo"
		and target_3.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vestate_1734, FunctionCall target_13) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ExecGetInsertedCols")
		and target_4.getArgument(0).(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_4.getArgument(1).(VariableAccess).getTarget()=vestate_1734
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bms_union")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="insertedCols"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="updatedCols"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_4.getArgument(1).(VariableAccess).getLocation().isBefore(target_13.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_5(Parameter vestate_1734, FunctionCall target_14) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ExecGetUpdatedCols")
		and target_5.getArgument(0).(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_5.getArgument(1).(VariableAccess).getTarget()=vestate_1734
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bms_union")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="insertedCols"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="updatedCols"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_14.getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vestate_1734, Variable vmodifiedCols_1739, Parameter vresultRelInfo_1732, PointerFieldAccess target_0, FunctionCall target_14, ExprStmt target_16) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmodifiedCols_1739
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bms_union")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ExecGetInsertedCols")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_1732
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_1734
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ExecGetUpdatedCols")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_1732
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_1734
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_0
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_14.getArgument(1).(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_7(Parameter vresultRelInfo_1732, VariableAccess target_7) {
		target_7.getTarget()=vresultRelInfo_1732
		and target_7.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_8(Parameter vestate_1734, VariableAccess target_8) {
		target_8.getTarget()=vestate_1734
		and target_8.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_9(Parameter vresultRelInfo_1732, VariableAccess target_9) {
		target_9.getTarget()=vresultRelInfo_1732
		and target_9.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_10(Parameter vestate_1734, VariableAccess target_10) {
		target_10.getTarget()=vestate_1734
		and target_10.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_11(Parameter vestate_1734, Parameter vresultRelInfo_1732, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="insertedCols"
		and target_11.getQualifier().(FunctionCall).getTarget().hasName("exec_rt_fetch")
		and target_11.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_11.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
		and target_11.getQualifier().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_1734
}

predicate func_12(Parameter vestate_1734, Parameter vresultRelInfo_1732, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="updatedCols"
		and target_12.getQualifier().(FunctionCall).getTarget().hasName("exec_rt_fetch")
		and target_12.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_12.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
		and target_12.getQualifier().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_1734
}

predicate func_13(Parameter vestate_1734, Parameter vresultRelInfo_1732, FunctionCall target_13) {
		target_13.getTarget().hasName("exec_rt_fetch")
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
		and target_13.getArgument(1).(VariableAccess).getTarget()=vestate_1734
}

predicate func_14(Parameter vestate_1734, Parameter vresultRelInfo_1732, FunctionCall target_14) {
		target_14.getTarget().hasName("exec_rt_fetch")
		and target_14.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_14.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
		and target_14.getArgument(1).(VariableAccess).getTarget()=vestate_1734
}

predicate func_16(Parameter vresultRelInfo_1732, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TupleDesc")
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1732
}

from Function func, Parameter vestate_1734, Variable vmodifiedCols_1739, Parameter vresultRelInfo_1732, PointerFieldAccess target_0, PointerFieldAccess target_1, PointerFieldAccess target_2, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, PointerFieldAccess target_11, PointerFieldAccess target_12, FunctionCall target_13, FunctionCall target_14, ExprStmt target_16
where
func_0(vresultRelInfo_1732, target_0)
and func_1(vresultRelInfo_1732, target_1)
and func_2(vresultRelInfo_1732, target_2)
and not func_3(vresultRelInfo_1732, target_13)
and not func_4(vestate_1734, target_13)
and not func_5(vestate_1734, target_14)
and not func_6(vestate_1734, vmodifiedCols_1739, vresultRelInfo_1732, target_0, target_14, target_16)
and func_7(vresultRelInfo_1732, target_7)
and func_8(vestate_1734, target_8)
and func_9(vresultRelInfo_1732, target_9)
and func_10(vestate_1734, target_10)
and func_11(vestate_1734, vresultRelInfo_1732, target_11)
and func_12(vestate_1734, vresultRelInfo_1732, target_12)
and func_13(vestate_1734, vresultRelInfo_1732, target_13)
and func_14(vestate_1734, vresultRelInfo_1732, target_14)
and func_16(vresultRelInfo_1732, target_16)
and vestate_1734.getType().hasName("EState *")
and vmodifiedCols_1739.getType().hasName("Bitmapset *")
and vresultRelInfo_1732.getType().hasName("ResultRelInfo *")
and vestate_1734.getFunction() = func
and vmodifiedCols_1739.(LocalVariable).getFunction() = func
and vresultRelInfo_1732.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
