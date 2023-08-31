/**
 * @name postgresql-b7d1f32ff6588be99844c140ec1aacb6e44f4b84-ExecInitModifyTable
 * @id cpp/postgresql/b7d1f32ff6588be99844c140ec1aacb6e44f4b84/ExecInitModifyTable
 * @description postgresql-b7d1f32ff6588be99844c140ec1aacb6e44f4b84-src/backend/executor/nodeModifyTable.c-ExecInitModifyTable CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmtstate_2296, Variable vtupDesc_2538, ExprStmt target_20, ConditionalExpr target_21, ExprStmt target_22, VariableAccess target_0) {
		target_0.getTarget()=vtupDesc_2538
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitExtraTupleSlot")
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="mt_partition_tuple_routing"
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getParent().(ConditionalExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Variable vmtstate_2296, Variable vresultRelInfo_2300, Variable vecontext_2536, Variable vrelationDesc_2537, Parameter vnode_2294, FunctionCall target_1) {
		target_1.getTarget().hasName("ExecBuildProjectionInfo")
		and not target_1.getTarget().hasName("ExecBuildProjectionInfoExt")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_2294
		and target_1.getArgument(1).(VariableAccess).getTarget()=vecontext_2536
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_1.getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ps"
		and target_1.getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_1.getArgument(4).(VariableAccess).getTarget()=vrelationDesc_2537
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oc_ProjInfo"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
}

predicate func_5(Variable vresultRelInfo_2300, Parameter vnode_2294, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ExecCheckPlanOutput")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_5.getArgument(1).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_2294
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_26.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Variable vresultRelInfo_2300, Variable vCurrentMemoryContext, Variable v_result_2565, StmtExpr target_9) {
		target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v_result_2565
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("MemoryContextAllocZeroAligned")
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="32"
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("MemoryContextAllocZero")
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="32"
		and target_9.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_9.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=v_result_2565
		and target_9.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(VariableAccess).getTarget()=v_result_2565
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_9.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
}

predicate func_10(Parameter vnode_2294, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="onConflictSet"
		and target_10.getQualifier().(VariableAccess).getTarget()=vnode_2294
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_11(Variable vresultRelInfo_2300, VariableAccess target_11) {
		target_11.getTarget()=vresultRelInfo_2300
}

predicate func_12(Variable vrelationDesc_2537, VariableAccess target_12) {
		target_12.getTarget()=vrelationDesc_2537
		and target_12.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_14(Variable vrelationDesc_2537, Variable vtupDesc_2538, Parameter vnode_2294, VariableAccess target_14) {
		target_14.getTarget()=vtupDesc_2538
		and target_14.getParent().(AssignExpr).getLValue() = target_14
		and target_14.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecTypeFromTL")
		and target_14.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_14.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_2294
		and target_14.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdhasoid"
		and target_14.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelationDesc_2537
}

/*predicate func_15(Variable vrelationDesc_2537, Variable vtupDesc_2538, Parameter vnode_2294, FunctionCall target_15) {
		target_15.getTarget().hasName("ExecTypeFromTL")
		and target_15.getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_15.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_2294
		and target_15.getArgument(1).(PointerFieldAccess).getTarget().getName()="tdhasoid"
		and target_15.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrelationDesc_2537
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupDesc_2538
}

*/
predicate func_16(Variable vresultRelInfo_2300, Variable vtupDesc_2538, AssignExpr target_16) {
		target_16.getLValue().(PointerFieldAccess).getTarget().getName()="oc_ProjTupdesc"
		and target_16.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_16.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_16.getRValue().(VariableAccess).getTarget()=vtupDesc_2538
}

/*predicate func_17(Variable vresultRelInfo_2300, ExprStmt target_24, ExprStmt target_25, PointerFieldAccess target_17) {
		target_17.getTarget().getName()="ri_onConflict"
		and target_17.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(VariableAccess).getLocation())
		and target_17.getQualifier().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_18(Variable vresultRelInfo_2300, ExprStmt target_28, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="ri_onConflict"
		and target_18.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_18.getQualifier().(VariableAccess).getLocation().isBefore(target_28.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_19(Variable vresultRelInfo_2300, ExprStmt target_25, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="ri_onConflict"
		and target_19.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getQualifier().(VariableAccess).getLocation())
}

predicate func_20(Variable vmtstate_2296, Variable vtupDesc_2538, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitExtraTupleSlot")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="state"
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="mt_partition_tuple_routing"
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(VariableAccess).getTarget()=vtupDesc_2538
}

predicate func_21(Variable vmtstate_2296, Variable vtupDesc_2538, ConditionalExpr target_21) {
		target_21.getCondition().(PointerFieldAccess).getTarget().getName()="mt_partition_tuple_routing"
		and target_21.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_21.getThen().(Literal).getValue()="0"
		and target_21.getElse().(VariableAccess).getTarget()=vtupDesc_2538
}

predicate func_22(Variable vtupDesc_2538, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupDesc_2538
		and target_22.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_24(Variable vresultRelInfo_2300, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_24.getExpr().(AssignExpr).getRValue() instanceof StmtExpr
}

predicate func_25(Variable vresultRelInfo_2300, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oc_ProjInfo"
		and target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_25.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_26(Variable vmtstate_2296, Parameter vnode_2294, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mt_excludedtlist"
		and target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_2296
		and target_26.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="exclRelTlist"
		and target_26.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_2294
}

predicate func_28(Variable vresultRelInfo_2300, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oc_WhereClause"
		and target_28.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflict"
		and target_28.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2300
		and target_28.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("ExprState *")
}

from Function func, Variable vmtstate_2296, Variable vresultRelInfo_2300, Variable vCurrentMemoryContext, Variable vecontext_2536, Variable vrelationDesc_2537, Variable vtupDesc_2538, Variable v_result_2565, Parameter vnode_2294, VariableAccess target_0, FunctionCall target_1, StmtExpr target_9, PointerFieldAccess target_10, VariableAccess target_11, VariableAccess target_12, VariableAccess target_14, AssignExpr target_16, PointerFieldAccess target_18, PointerFieldAccess target_19, ExprStmt target_20, ConditionalExpr target_21, ExprStmt target_22, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_28
where
func_0(vmtstate_2296, vtupDesc_2538, target_20, target_21, target_22, target_0)
and func_1(vmtstate_2296, vresultRelInfo_2300, vecontext_2536, vrelationDesc_2537, vnode_2294, target_1)
and not func_5(vresultRelInfo_2300, vnode_2294, target_24, target_25, target_26)
and func_9(vresultRelInfo_2300, vCurrentMemoryContext, v_result_2565, target_9)
and func_10(vnode_2294, target_10)
and func_11(vresultRelInfo_2300, target_11)
and func_12(vrelationDesc_2537, target_12)
and func_14(vrelationDesc_2537, vtupDesc_2538, vnode_2294, target_14)
and func_16(vresultRelInfo_2300, vtupDesc_2538, target_16)
and func_18(vresultRelInfo_2300, target_28, target_18)
and func_19(vresultRelInfo_2300, target_25, target_19)
and func_20(vmtstate_2296, vtupDesc_2538, target_20)
and func_21(vmtstate_2296, vtupDesc_2538, target_21)
and func_22(vtupDesc_2538, target_22)
and func_24(vresultRelInfo_2300, target_24)
and func_25(vresultRelInfo_2300, target_25)
and func_26(vmtstate_2296, vnode_2294, target_26)
and func_28(vresultRelInfo_2300, target_28)
and vmtstate_2296.getType().hasName("ModifyTableState *")
and vresultRelInfo_2300.getType().hasName("ResultRelInfo *")
and vCurrentMemoryContext.getType().hasName("MemoryContext")
and vecontext_2536.getType().hasName("ExprContext *")
and vrelationDesc_2537.getType().hasName("TupleDesc")
and vtupDesc_2538.getType().hasName("TupleDesc")
and v_result_2565.getType().hasName("Node *")
and vnode_2294.getType().hasName("ModifyTable *")
and vmtstate_2296.(LocalVariable).getFunction() = func
and vresultRelInfo_2300.(LocalVariable).getFunction() = func
and not vCurrentMemoryContext.getParentScope+() = func
and vecontext_2536.(LocalVariable).getFunction() = func
and vrelationDesc_2537.(LocalVariable).getFunction() = func
and vtupDesc_2538.(LocalVariable).getFunction() = func
and v_result_2565.(LocalVariable).getFunction() = func
and vnode_2294.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
