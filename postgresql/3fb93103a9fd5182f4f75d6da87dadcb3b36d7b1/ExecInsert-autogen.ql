/**
 * @name postgresql-3fb93103a9fd5182f4f75d6da87dadcb3b36d7b1-ExecInsert
 * @id cpp/postgresql/3fb93103a9fd5182f4f75d6da87dadcb3b36d7b1/ExecInsert
 * @description postgresql-3fb93103a9fd5182f4f75d6da87dadcb3b36d7b1-src/backend/executor/nodeModifyTable.c-ExecInsert CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresultRelInfo_356, ExprStmt target_12, VariableAccess target_0) {
		target_0.getTarget()=vresultRelInfo_356
		and target_0.getParent().(PointerFieldAccess).getParent().(IfStmt).getThen()=target_12
}

predicate func_1(Parameter vslot_351, Variable vresultRelInfo_356, Variable vresultRelationDesc_357, PointerFieldAccess target_13, ExprStmt target_14, IfStmt target_15, ExprStmt target_16) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresultRelInfo_356
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vslot_351
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("AttrNumber *")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("convert_tuples_by_name_map_if_req")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_357
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Relation")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="could not convert row type"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(VariableAccess).getType().hasName("AttrNumber *")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslot_351
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("execute_attr_map_slot")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tts_tid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tts_tid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tts_tableOid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tts_tableOid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pfree")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("AttrNumber *")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_14.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_15.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vresultRelationDesc_357, ExprStmt target_16) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("AttrNumber *")
		and target_2.getRValue().(FunctionCall).getTarget().hasName("convert_tuples_by_name_map_if_req")
		and target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_357
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Relation")
		and target_2.getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="could not convert row type"
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Parameter vslot_351, Variable vresult_359) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("execute_attr_map_slot")
		and target_4.getArgument(0).(VariableAccess).getType().hasName("AttrNumber *")
		and target_4.getArgument(1).(VariableAccess).getTarget()=vslot_351
		and target_4.getArgument(2).(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_359)
}

*/
predicate func_5(Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelationDesc_357, Variable vresult_359, PointerFieldAccess target_13, ExprStmt target_12, FunctionCall target_17, ReturnStmt target_18) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_359
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_projectReturning"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_id"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_357
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vslot_351
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vplanSlot_352
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_17.getArgument(3).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_18.getExpr().(VariableAccess).getLocation()))
}

/*predicate func_6(Function func) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="ri_projectReturning"
		and target_6.getQualifier().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_9(Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelInfo_356, Variable vresult_359, VariableAccess target_9) {
		target_9.getTarget()=vresult_359
		and target_9.getParent().(AssignExpr).getLValue() = target_9
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_356
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_351
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_352
}

/*predicate func_10(Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelInfo_356, VariableAccess target_10) {
		target_10.getTarget()=vslot_351
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_356
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_352
}

*/
/*predicate func_11(Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelInfo_356, VariableAccess target_11) {
		target_11.getTarget()=vresultRelInfo_356
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_351
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_352
}

*/
predicate func_12(Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelInfo_356, Variable vresult_359, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_359
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_356
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_351
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_352
}

predicate func_13(Variable vresultRelInfo_356, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="ri_projectReturning"
		and target_13.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_356
}

predicate func_14(Parameter vslot_351, Variable vresultRelInfo_356, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("ExecWithCheckOptions")
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_356
		and target_14.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vslot_351
		and target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("EState *")
}

predicate func_15(Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelInfo_356, Variable vresult_359, IfStmt target_15) {
		target_15.getCondition().(PointerFieldAccess).getTarget().getName()="ri_projectReturning"
		and target_15.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_356
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_359
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_356
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_351
		and target_15.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_352
}

predicate func_16(Parameter vslot_351, Variable vresultRelationDesc_357, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("table_tuple_insert")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelationDesc_357
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_351
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="es_output_cid"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EState *")
		and target_16.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_16.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_17(Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelInfo_356, FunctionCall target_17) {
		target_17.getTarget().hasName("ExecOnConflictUpdate")
		and target_17.getArgument(0).(VariableAccess).getTarget().getType().hasName("ModifyTableState *")
		and target_17.getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_356
		and target_17.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("ItemPointerData")
		and target_17.getArgument(3).(VariableAccess).getTarget()=vplanSlot_352
		and target_17.getArgument(4).(VariableAccess).getTarget()=vslot_351
		and target_17.getArgument(5).(VariableAccess).getTarget().getType().hasName("EState *")
		and target_17.getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_17.getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_18(Variable vresult_359, ReturnStmt target_18) {
		target_18.getExpr().(VariableAccess).getTarget()=vresult_359
}

from Function func, Parameter vslot_351, Parameter vplanSlot_352, Variable vresultRelInfo_356, Variable vresultRelationDesc_357, Variable vresult_359, VariableAccess target_0, VariableAccess target_9, ExprStmt target_12, PointerFieldAccess target_13, ExprStmt target_14, IfStmt target_15, ExprStmt target_16, FunctionCall target_17, ReturnStmt target_18
where
func_0(vresultRelInfo_356, target_12, target_0)
and not func_1(vslot_351, vresultRelInfo_356, vresultRelationDesc_357, target_13, target_14, target_15, target_16)
and not func_5(vslot_351, vplanSlot_352, vresultRelationDesc_357, vresult_359, target_13, target_12, target_17, target_18)
and func_9(vslot_351, vplanSlot_352, vresultRelInfo_356, vresult_359, target_9)
and func_12(vslot_351, vplanSlot_352, vresultRelInfo_356, vresult_359, target_12)
and func_13(vresultRelInfo_356, target_13)
and func_14(vslot_351, vresultRelInfo_356, target_14)
and func_15(vslot_351, vplanSlot_352, vresultRelInfo_356, vresult_359, target_15)
and func_16(vslot_351, vresultRelationDesc_357, target_16)
and func_17(vslot_351, vplanSlot_352, vresultRelInfo_356, target_17)
and func_18(vresult_359, target_18)
and vslot_351.getType().hasName("TupleTableSlot *")
and vplanSlot_352.getType().hasName("TupleTableSlot *")
and vresultRelInfo_356.getType().hasName("ResultRelInfo *")
and vresultRelationDesc_357.getType().hasName("Relation")
and vresult_359.getType().hasName("TupleTableSlot *")
and vslot_351.getFunction() = func
and vplanSlot_352.getFunction() = func
and vresultRelInfo_356.(LocalVariable).getFunction() = func
and vresultRelationDesc_357.(LocalVariable).getFunction() = func
and vresult_359.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
