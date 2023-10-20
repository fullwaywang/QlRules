/**
 * @name postgresql-27835b5476642d6a4eeb06e32095d29daeb9c585-ExecInsert
 * @id cpp/postgresql/27835b5476642d6a4eeb06e32095d29daeb9c585/ExecInsert
 * @description postgresql-27835b5476642d6a4eeb06e32095d29daeb9c585-src/backend/executor/nodeModifyTable.c-ExecInsert CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vresultRelInfo_270, ExprStmt target_10, VariableAccess target_0) {
		target_0.getTarget()=vresultRelInfo_270
		and target_0.getParent().(PointerFieldAccess).getParent().(IfStmt).getThen()=target_10
}

predicate func_1(Parameter vslot_264, Variable vresultRelInfo_270, Variable vresultRelationDesc_271, PointerFieldAccess target_11, ExprStmt target_12, ExprStmt target_10, IfStmt target_13) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresultRelInfo_270
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vslot_264
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("TupleConversionMap *")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("convert_tuples_by_name")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_271
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Relation")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="could not convert row type"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(VariableAccess).getType().hasName("TupleConversionMap *")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("HeapTuple")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("do_convert_tuple")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="t_self"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="t_tableOid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="t_tableOid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="t_xmin"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="t_xmin"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(6).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="t_xmax"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(8).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="tdhasoid"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(8).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslot_264
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecStoreTuple")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free_conversion_map")
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("TupleConversionMap *")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_13.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vresultRelationDesc_271) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("TupleConversionMap *")
		and target_2.getRValue().(FunctionCall).getTarget().hasName("convert_tuples_by_name")
		and target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_2.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_271
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_2.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Relation")
		and target_2.getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="could not convert row type")
}

*/
/*predicate func_4(Variable vresult_274) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ExecStoreTuple")
		and target_4.getArgument(0).(VariableAccess).getType().hasName("HeapTuple")
		and target_4.getArgument(1).(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_4.getArgument(2).(Literal).getValue()="0"
		and target_4.getArgument(3).(Literal).getValue()="1"
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_274)
}

*/
predicate func_5(Parameter vslot_264, Parameter vplanSlot_265, Variable vresultRelationDesc_271, Variable vresult_274, PointerFieldAccess target_11, FunctionCall target_14, ReturnStmt target_15) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_274
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_projectReturning"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rd_id"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelationDesc_271
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vslot_264
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vplanSlot_265
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_14.getArgument(3).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getExpr().(VariableAccess).getLocation()))
}

/*predicate func_6(Function func) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="ri_projectReturning"
		and target_6.getQualifier().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_8(Parameter vslot_264, Parameter vplanSlot_265, Variable vresultRelInfo_270, Variable vresult_274, VariableAccess target_8) {
		target_8.getTarget()=vresult_274
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_270
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_264
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_265
}

/*predicate func_9(Parameter vslot_264, Parameter vplanSlot_265, Variable vresultRelInfo_270, VariableAccess target_9) {
		target_9.getTarget()=vresultRelInfo_270
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_264
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_265
}

*/
predicate func_10(Parameter vslot_264, Parameter vplanSlot_265, Variable vresultRelInfo_270, Variable vresult_274, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_274
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_270
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_264
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_265
}

predicate func_11(Variable vresultRelInfo_270, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="ri_projectReturning"
		and target_11.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_270
}

predicate func_12(Parameter vslot_264, Variable vresultRelInfo_270, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("ExecWithCheckOptions")
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_270
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vslot_264
		and target_12.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("EState *")
}

predicate func_13(Parameter vslot_264, Parameter vplanSlot_265, Variable vresultRelInfo_270, Variable vresult_274, IfStmt target_13) {
		target_13.getCondition().(PointerFieldAccess).getTarget().getName()="ri_projectReturning"
		and target_13.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_270
		and target_13.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_274
		and target_13.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecProcessReturning")
		and target_13.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_270
		and target_13.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vslot_264
		and target_13.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplanSlot_265
}

predicate func_14(Parameter vslot_264, Parameter vplanSlot_265, Variable vresultRelInfo_270, FunctionCall target_14) {
		target_14.getTarget().hasName("ExecOnConflictUpdate")
		and target_14.getArgument(0).(VariableAccess).getTarget().getType().hasName("ModifyTableState *")
		and target_14.getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_270
		and target_14.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("ItemPointerData")
		and target_14.getArgument(3).(VariableAccess).getTarget()=vplanSlot_265
		and target_14.getArgument(4).(VariableAccess).getTarget()=vslot_264
		and target_14.getArgument(5).(VariableAccess).getTarget().getType().hasName("EState *")
		and target_14.getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
		and target_14.getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
}

predicate func_15(Variable vresult_274, ReturnStmt target_15) {
		target_15.getExpr().(VariableAccess).getTarget()=vresult_274
}

from Function func, Parameter vslot_264, Parameter vplanSlot_265, Variable vresultRelInfo_270, Variable vresultRelationDesc_271, Variable vresult_274, VariableAccess target_0, VariableAccess target_8, ExprStmt target_10, PointerFieldAccess target_11, ExprStmt target_12, IfStmt target_13, FunctionCall target_14, ReturnStmt target_15
where
func_0(vresultRelInfo_270, target_10, target_0)
and not func_1(vslot_264, vresultRelInfo_270, vresultRelationDesc_271, target_11, target_12, target_10, target_13)
and not func_5(vslot_264, vplanSlot_265, vresultRelationDesc_271, vresult_274, target_11, target_14, target_15)
and func_8(vslot_264, vplanSlot_265, vresultRelInfo_270, vresult_274, target_8)
and func_10(vslot_264, vplanSlot_265, vresultRelInfo_270, vresult_274, target_10)
and func_11(vresultRelInfo_270, target_11)
and func_12(vslot_264, vresultRelInfo_270, target_12)
and func_13(vslot_264, vplanSlot_265, vresultRelInfo_270, vresult_274, target_13)
and func_14(vslot_264, vplanSlot_265, vresultRelInfo_270, target_14)
and func_15(vresult_274, target_15)
and vslot_264.getType().hasName("TupleTableSlot *")
and vplanSlot_265.getType().hasName("TupleTableSlot *")
and vresultRelInfo_270.getType().hasName("ResultRelInfo *")
and vresultRelationDesc_271.getType().hasName("Relation")
and vresult_274.getType().hasName("TupleTableSlot *")
and vslot_264.getFunction() = func
and vplanSlot_265.getFunction() = func
and vresultRelInfo_270.(LocalVariable).getFunction() = func
and vresultRelationDesc_271.(LocalVariable).getFunction() = func
and vresult_274.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
