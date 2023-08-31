/**
 * @name postgresql-a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3-ExecInsert
 * @id cpp/postgresql/a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3/ExecInsert
 * @description postgresql-a71cfc56bf6013e3ea1d673acaf73fe7ebbd6bf3-src/backend/executor/nodeModifyTable.c-ExecInsert CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresultRelInfo_381, ExprStmt target_12, VariableAccess target_0) {
		target_0.getTarget()=vresultRelInfo_381
		and target_0.getParent().(PointerFieldAccess).getParent().(IfStmt).getThen()=target_12
}

predicate func_1(Parameter vslot_376, Variable vresultRelInfo_381, Variable vresultRelationDesc_382, PointerFieldAccess target_13, ExprStmt target_14, IfStmt target_15, ExprStmt target_16) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresultRelInfo_381
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vslot_376
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("AttrMap *")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("build_attrmap_by_name_if_req")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_382
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Relation")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(VariableAccess).getType().hasName("AttrMap *")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslot_376
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("execute_attr_map_slot")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tts_tid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tts_tid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tts_tableOid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tts_tableOid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free_attrmap")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("AttrMap *")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_14.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_15.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vresultRelationDesc_382, ExprStmt target_16) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("AttrMap *")
		and target_2.getRValue().(FunctionCall).getTarget().hasName("build_attrmap_by_name_if_req")
		and target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_382
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Relation")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Parameter vslot_376, Variable vresult_384) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("execute_attr_map_slot")
		and target_4.getArgument(0).(VariableAccess).getType().hasName("AttrMap *")
		and target_4.getArgument(1).(VariableAccess).getTarget()=vslot_376
		and target_4.getArgument(2).(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_384)
}

*/
predicate func_5(Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelationDesc_382, Variable vresult_384, PointerFieldAccess target_13, ExprStmt target_12, FunctionCall target_17, ReturnStmt target_19) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_384
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_projectReturning"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_id"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_382
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vslot_376
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vplanSlot_377
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_17.getArgument(3).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_19.getExpr().(VariableAccess).getLocation()))
}

/*predicate func_6(Function func) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="ri_projectReturning"
		and target_6.getQualifier().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_9(Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelInfo_381, Variable vresult_384, VariableAccess target_9) {
		target_9.getTarget()=vresult_384
		and target_9.getParent().(AssignExpr).getLValue() = target_9
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_381
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_376
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_377
}

/*predicate func_10(Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelInfo_381, VariableAccess target_10) {
		target_10.getTarget()=vslot_376
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_381
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_377
}

*/
/*predicate func_11(Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelInfo_381, VariableAccess target_11) {
		target_11.getTarget()=vresultRelInfo_381
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_376
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_377
}

*/
predicate func_12(Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelInfo_381, Variable vresult_384, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_384
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_381
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_376
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_377
}

predicate func_13(Variable vresultRelInfo_381, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="ri_projectReturning"
		and target_13.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_381
}

predicate func_14(Parameter vslot_376, Variable vresultRelInfo_381, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("ExecWithCheckOptions")
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_381
		and target_14.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vslot_376
		and target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("EState *")
}

predicate func_15(Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelInfo_381, Variable vresult_384, IfStmt target_15) {
		target_15.getCondition().(PointerFieldAccess).getTarget().getName()="ri_projectReturning"
		and target_15.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_381
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_384
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_381
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_376
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_377
}

predicate func_16(Parameter vslot_376, Variable vresultRelationDesc_382, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("table_tuple_insert")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelationDesc_382
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_376
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="es_output_cid"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EState *")
		and target_16.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_16.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_17(Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelInfo_381, FunctionCall target_17) {
		target_17.getTarget().hasName("ExecOnConflictUpdate")
		and target_17.getArgument(0).(VariableAccess).getTarget().getType().hasName("ModifyTableState *")
		and target_17.getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_381
		and target_17.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("ItemPointerData")
		and target_17.getArgument(3).(VariableAccess).getTarget()=vplanSlot_377
		and target_17.getArgument(4).(VariableAccess).getTarget()=vslot_376
		and target_17.getArgument(5).(VariableAccess).getTarget().getType().hasName("EState *")
		and target_17.getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_17.getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_19(Variable vresult_384, ReturnStmt target_19) {
		target_19.getExpr().(VariableAccess).getTarget()=vresult_384
}

from Function func, Parameter vslot_376, Parameter vplanSlot_377, Variable vresultRelInfo_381, Variable vresultRelationDesc_382, Variable vresult_384, VariableAccess target_0, VariableAccess target_9, ExprStmt target_12, PointerFieldAccess target_13, ExprStmt target_14, IfStmt target_15, ExprStmt target_16, FunctionCall target_17, ReturnStmt target_19
where
func_0(vresultRelInfo_381, target_12, target_0)
and not func_1(vslot_376, vresultRelInfo_381, vresultRelationDesc_382, target_13, target_14, target_15, target_16)
and not func_5(vslot_376, vplanSlot_377, vresultRelationDesc_382, vresult_384, target_13, target_12, target_17, target_19)
and func_9(vslot_376, vplanSlot_377, vresultRelInfo_381, vresult_384, target_9)
and func_12(vslot_376, vplanSlot_377, vresultRelInfo_381, vresult_384, target_12)
and func_13(vresultRelInfo_381, target_13)
and func_14(vslot_376, vresultRelInfo_381, target_14)
and func_15(vslot_376, vplanSlot_377, vresultRelInfo_381, vresult_384, target_15)
and func_16(vslot_376, vresultRelationDesc_382, target_16)
and func_17(vslot_376, vplanSlot_377, vresultRelInfo_381, target_17)
and func_19(vresult_384, target_19)
and vslot_376.getType().hasName("TupleTableSlot *")
and vplanSlot_377.getType().hasName("TupleTableSlot *")
and vresultRelInfo_381.getType().hasName("ResultRelInfo *")
and vresultRelationDesc_382.getType().hasName("Relation")
and vresult_384.getType().hasName("TupleTableSlot *")
and vslot_376.getFunction() = func
and vplanSlot_377.getFunction() = func
and vresultRelInfo_381.(LocalVariable).getFunction() = func
and vresultRelationDesc_382.(LocalVariable).getFunction() = func
and vresult_384.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
