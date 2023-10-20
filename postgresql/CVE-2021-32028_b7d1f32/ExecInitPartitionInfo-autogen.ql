/**
 * @name postgresql-b7d1f32ff6588be99844c140ec1aacb6e44f4b84-ExecInitPartitionInfo
 * @id cpp/postgresql/b7d1f32ff6588be99844c140ec1aacb6e44f4b84/ExecInitPartitionInfo
 * @description postgresql-b7d1f32ff6588be99844c140ec1aacb6e44f4b84-src/backend/executor/execPartition.c-ExecInitPartitionInfo CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtupDesc_633, Parameter vmtstate_370, ExprStmt target_18, ExprStmt target_15, ValueFieldAccess target_19, VariableAccess target_0) {
		target_0.getTarget()=vtupDesc_633
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecSetSlotDescriptor")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_370
		and target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter vmtstate_370, Variable vleaf_part_rri_379, Variable vpartrelDesc_571, Variable vecontext_572, Variable vonconflset_632, FunctionCall target_1) {
		target_1.getTarget().hasName("ExecBuildProjectionInfo")
		and not target_1.getTarget().hasName("ExecBuildProjectionInfoExt")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vonconflset_632
		and target_1.getArgument(1).(VariableAccess).getTarget()=vecontext_572
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_370
		and target_1.getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ps"
		and target_1.getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_370
		and target_1.getArgument(4).(VariableAccess).getTarget()=vpartrelDesc_571
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oc_ProjInfo"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
}

predicate func_8(Variable v_result_636, Variable vleaf_part_rri_379, Variable vCurrentMemoryContext, StmtExpr target_8) {
		target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v_result_636
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("MemoryContextAllocZeroAligned")
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="32"
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("MemoryContextAllocZero")
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="32"
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=v_result_636
		and target_8.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableAccess).getTarget()=v_result_636
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
}

predicate func_9(Variable vonconflset_632, VariableAccess target_9) {
		target_9.getTarget()=vonconflset_632
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_10(Variable vpartrelDesc_571, VariableAccess target_10) {
		target_10.getTarget()=vpartrelDesc_571
		and target_10.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_12(Variable vtupDesc_633, Variable vpartrelDesc_571, Variable vonconflset_632, VariableAccess target_12) {
		target_12.getTarget()=vtupDesc_633
		and target_12.getParent().(AssignExpr).getLValue() = target_12
		and target_12.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecTypeFromTL")
		and target_12.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vonconflset_632
		and target_12.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdhasoid"
		and target_12.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpartrelDesc_571
}

/*predicate func_13(Variable vtupDesc_633, Variable vpartrelDesc_571, Variable vonconflset_632, FunctionCall target_13) {
		target_13.getTarget().hasName("ExecTypeFromTL")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vonconflset_632
		and target_13.getArgument(1).(PointerFieldAccess).getTarget().getName()="tdhasoid"
		and target_13.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpartrelDesc_571
		and target_13.getParent().(AssignExpr).getRValue() = target_13
		and target_13.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupDesc_633
}

*/
predicate func_14(Variable vleaf_part_rri_379, ExprStmt target_21, ExprStmt target_15, PointerFieldAccess target_14) {
		target_14.getTarget().getName()="ri_onConflict"
		and target_14.getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getQualifier().(VariableAccess).getLocation())
		and target_14.getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_15(Variable vtupDesc_633, Variable vleaf_part_rri_379, EqualityOperation target_22, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oc_ProjTupdesc"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtupDesc_633
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

/*predicate func_16(Variable vleaf_part_rri_379, ExprStmt target_23, ExprStmt target_24, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="ri_onConflict"
		and target_16.getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getQualifier().(VariableAccess).getLocation())
		and target_16.getQualifier().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_17(Variable vleaf_part_rri_379, ExprStmt target_15, ExprStmt target_25, PointerFieldAccess target_17) {
		target_17.getTarget().getName()="ri_onConflict"
		and target_17.getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(VariableAccess).getLocation())
		and target_17.getQualifier().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_18(Variable vtupDesc_633, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupDesc_633
		and target_18.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_19(Parameter vmtstate_370, ValueFieldAccess target_19) {
		target_19.getTarget().getName()="ps_ExprContext"
		and target_19.getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_370
}

predicate func_21(Variable vleaf_part_rri_379, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
		and target_21.getExpr().(AssignExpr).getRValue() instanceof StmtExpr
}

predicate func_22(EqualityOperation target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget().getType().hasName("TupleConversionMap *")
		and target_22.getAnOperand().(Literal).getValue()="0"
}

predicate func_23(Variable vleaf_part_rri_379, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oc_ProjInfo"
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
		and target_23.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_24(Parameter vmtstate_370, Variable vleaf_part_rri_379, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oc_WhereClause"
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_379
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitQual")
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("List *")
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ps"
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_370
}

predicate func_25(Variable vleaf_part_rri_379, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="partitions"
		and target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PartitionTupleRouting *")
		and target_25.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_25.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vleaf_part_rri_379
}

from Function func, Variable vtupDesc_633, Variable v_result_636, Parameter vmtstate_370, Variable vleaf_part_rri_379, Variable vCurrentMemoryContext, Variable vpartrelDesc_571, Variable vecontext_572, Variable vonconflset_632, VariableAccess target_0, FunctionCall target_1, StmtExpr target_8, VariableAccess target_9, VariableAccess target_10, VariableAccess target_12, PointerFieldAccess target_14, ExprStmt target_15, PointerFieldAccess target_17, ExprStmt target_18, ValueFieldAccess target_19, ExprStmt target_21, EqualityOperation target_22, ExprStmt target_23, ExprStmt target_24, ExprStmt target_25
where
func_0(vtupDesc_633, vmtstate_370, target_18, target_15, target_19, target_0)
and func_1(vmtstate_370, vleaf_part_rri_379, vpartrelDesc_571, vecontext_572, vonconflset_632, target_1)
and func_8(v_result_636, vleaf_part_rri_379, vCurrentMemoryContext, target_8)
and func_9(vonconflset_632, target_9)
and func_10(vpartrelDesc_571, target_10)
and func_12(vtupDesc_633, vpartrelDesc_571, vonconflset_632, target_12)
and func_14(vleaf_part_rri_379, target_21, target_15, target_14)
and func_15(vtupDesc_633, vleaf_part_rri_379, target_22, target_15)
and func_17(vleaf_part_rri_379, target_15, target_25, target_17)
and func_18(vtupDesc_633, target_18)
and func_19(vmtstate_370, target_19)
and func_21(vleaf_part_rri_379, target_21)
and func_22(target_22)
and func_23(vleaf_part_rri_379, target_23)
and func_24(vmtstate_370, vleaf_part_rri_379, target_24)
and func_25(vleaf_part_rri_379, target_25)
and vtupDesc_633.getType().hasName("TupleDesc")
and v_result_636.getType().hasName("Node *")
and vmtstate_370.getType().hasName("ModifyTableState *")
and vleaf_part_rri_379.getType().hasName("ResultRelInfo *")
and vCurrentMemoryContext.getType().hasName("MemoryContext")
and vpartrelDesc_571.getType().hasName("TupleDesc")
and vecontext_572.getType().hasName("ExprContext *")
and vonconflset_632.getType().hasName("List *")
and vtupDesc_633.(LocalVariable).getFunction() = func
and v_result_636.(LocalVariable).getFunction() = func
and vmtstate_370.getFunction() = func
and vleaf_part_rri_379.(LocalVariable).getFunction() = func
and not vCurrentMemoryContext.getParentScope+() = func
and vpartrelDesc_571.(LocalVariable).getFunction() = func
and vecontext_572.(LocalVariable).getFunction() = func
and vonconflset_632.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
