/**
 * @name postgresql-4a8656a7ee0c155b0249376af58eb3fc3a90415f-ExecBuildProjectionInfo
 * @id cpp/postgresql/4a8656a7ee0c155b0249376af58eb3fc3a90415f/ExecBuildProjectionInfo
 * @description postgresql-4a8656a7ee0c155b0249376af58eb3fc3a90415f-src/backend/executor/execExpr.c-ExecBuildProjectionInfo CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtargetList_353, Parameter vecontext_354, Parameter vslot_355, Parameter vparent_356, Parameter vinputDesc_357, ExprStmt target_23, RelationalOperation target_59) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ExecBuildProjectionInfoExt")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtargetList_353
		and target_0.getArgument(1).(VariableAccess).getTarget()=vecontext_354
		and target_0.getArgument(2).(VariableAccess).getTarget()=vslot_355
		and target_0.getArgument(3) instanceof Literal
		and target_0.getArgument(4).(VariableAccess).getTarget()=vparent_356
		and target_0.getArgument(5).(VariableAccess).getTarget()=vinputDesc_357
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_23.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(5).(VariableAccess).getLocation().isBefore(target_59.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vecontext_354, Variable vprojInfo_359, VariableAccess target_2) {
		target_2.getTarget()=vecontext_354
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pi_exprContext"
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_359
}

predicate func_3(Parameter vtargetList_353, Variable vstate_360, VariableAccess target_3) {
		target_3.getTarget()=vtargetList_353
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
}

predicate func_4(Parameter vparent_356, Variable vstate_360, VariableAccess target_4) {
		target_4.getTarget()=vparent_356
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
}

predicate func_5(Parameter vslot_355, Variable vstate_360, VariableAccess target_5) {
		target_5.getTarget()=vslot_355
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resultslot"
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
}

predicate func_6(Parameter vinputDesc_357, ExprStmt target_60, VariableAccess target_6) {
		target_6.getTarget()=vinputDesc_357
		and target_6.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_6.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_60
}

predicate func_7(Function func, DeclStmt target_7) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_9(Function func, ExprStmt target_9) {
		target_9.getExpr() instanceof Literal
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Variable v_result_359, Variable vCurrentMemoryContext, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v_result_359
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("MemoryContextAllocZeroAligned")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="128"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("MemoryContextAllocZero")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="128"
}

predicate func_11(Variable v_result_359, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=v_result_359
}

predicate func_12(Variable v_result_359, ExprStmt target_12) {
		target_12.getExpr().(VariableAccess).getTarget()=v_result_359
}

predicate func_13(Function func, DeclStmt target_13) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Function func, DeclStmt target_14) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Function func, DeclStmt target_15) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Parameter vecontext_354, Variable vprojInfo_359, Function func, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pi_exprContext"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_359
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vecontext_354
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Variable vprojInfo_359, Function func, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="tag"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_359
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Variable vprojInfo_359, Variable vstate_360, Function func, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_360
		and target_18.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_18.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_359
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

predicate func_19(Parameter vtargetList_353, Variable vstate_360, Function func, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtargetList_353
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Parameter vparent_356, Variable vstate_360, Function func, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="parent"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
		and target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vparent_356
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Variable vstate_360, Function func, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ext_params"
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Parameter vslot_355, Variable vstate_360, Function func, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resultslot"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
		and target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vslot_355
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
}

predicate func_23(Parameter vtargetList_353, Variable vstate_360, Function func, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("ExecInitExprSlots")
		and target_23.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and target_23.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtargetList_353
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_23
}

predicate func_24(Variable vlc_362, Variable vlc__state_378, Variable vvariable_381, Variable vattnum_382, Variable visSafeVar_383, Parameter vinputDesc_357, Variable vstate_360, Function func, ForStmt target_24) {
		target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="l"
		and target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlc__state_378
		and target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="i"
		and target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlc__state_378
		and target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="l"
		and target_24.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlc__state_378
		and target_24.getCondition().(ConditionalExpr).getThen().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlc_362
		and target_24.getCondition().(ConditionalExpr).getThen().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="elements"
		and target_24.getCondition().(ConditionalExpr).getThen().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="i"
		and target_24.getCondition().(ConditionalExpr).getThen().(CommaExpr).getRightOperand().(Literal).getValue()="1"
		and target_24.getCondition().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlc_362
		and target_24.getCondition().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_24.getCondition().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(Literal).getValue()="0"
		and target_24.getUpdate().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="i"
		and target_24.getUpdate().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlc__state_378
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="expr"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvariable_381
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_382
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinputDesc_357
		and target_24.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(VariableAccess).getTarget()=visSafeVar_383
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="varno"
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="attnum"
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecInitExprRec")
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_360
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_typlen")
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_24.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_24
}

/*predicate func_29(Variable vtle_380, Variable vvariable_381, Variable vattnum_382, Variable visSafeVar_383, Parameter vinputDesc_357, IfStmt target_29) {
		target_29.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="expr"
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_29.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_29.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvariable_381
		and target_29.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_29.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_29.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_382
		and target_29.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_29.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_381
		and target_29.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinputDesc_357
		and target_29.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_29.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_383
		and target_29.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_29.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vattnum_382
		and target_29.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_29.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinputDesc_357
}

*/
/*predicate func_30(Variable vtle_380, Variable vvariable_381, LogicalAndExpr target_61, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvariable_381
		and target_30.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_30.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_61
}

*/
/*predicate func_31(Variable vvariable_381, Variable vattnum_382, LogicalAndExpr target_61, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_382
		and target_31.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_31.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_381
		and target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_61
}

*/
/*predicate func_32(Variable vattnum_382, Variable visSafeVar_383, Parameter vinputDesc_357, LogicalAndExpr target_61, IfStmt target_32) {
		target_32.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinputDesc_357
		and target_32.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_32.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_383
		and target_32.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_32.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vattnum_382
		and target_32.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_32.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinputDesc_357
		and target_32.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="attisdropped"
		and target_32.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vartype"
		and target_32.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="atttypid"
		and target_32.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_61
}

*/
/*predicate func_33(RelationalOperation target_59, Function func, DeclStmt target_33) {
		target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
		and target_33.getEnclosingFunction() = func
}

*/
/*predicate func_34(Variable vvariable_381, Variable visSafeVar_383, Variable vattr_405, RelationalOperation target_59, IfStmt target_34) {
		target_34.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="attisdropped"
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_405
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vartype"
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_381
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="atttypid"
		and target_34.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_405
		and target_34.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_383
		and target_34.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

*/
/*predicate func_35(Variable visSafeVar_383, LogicalAndExpr target_62, ExprStmt target_60, IfStmt target_36, ExprStmt target_35) {
		target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_383
		and target_35.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
		and target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_36.getCondition().(VariableAccess).getLocation())
}

*/
predicate func_36(Variable vtle_380, Variable vvariable_381, Variable vattnum_382, Variable visSafeVar_383, Variable vstate_360, Variable vscratch_361, IfStmt target_36) {
		target_36.getCondition().(VariableAccess).getTarget()=visSafeVar_383
		and target_36.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="varno"
		and target_36.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_381
		and target_36.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="65000"
		and target_36.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="65001"
		and target_36.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(6).(SwitchCase).toString() = "default: "
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="attnum"
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattnum_382
		and target_36.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_36.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_36.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_36.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_36.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_36.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_36.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_36.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_36.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and target_36.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_361
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecInitExprRec")
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_360
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resvalue"
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resnull"
		and target_36.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_typlen")
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_36.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_36.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_36.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_tmp"
		and target_36.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_36.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_36.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_36.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_36.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_36.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and target_36.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_361
}

/*predicate func_37(Variable vvariable_381, Variable vscratch_361, SwitchStmt target_37) {
		target_37.getExpr().(PointerFieldAccess).getTarget().getName()="varno"
		and target_37.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_381
		and target_37.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="65000"
		and target_37.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_37.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_37.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="65001"
		and target_37.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_37.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_37.getStmt().(BlockStmt).getStmt(6).(SwitchCase).toString() = "default: "
		and target_37.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_37.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
}

*/
/*predicate func_38(Function func, SwitchCase target_38) {
		target_38.getExpr().(Literal).getValue()="65000"
		and target_38.getEnclosingFunction() = func
}

*/
/*predicate func_39(Variable vscratch_361, ExprStmt target_39) {
		target_39.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_39.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
}

*/
/*predicate func_41(Function func, SwitchCase target_41) {
		target_41.getExpr().(Literal).getValue()="65001"
		and target_41.getEnclosingFunction() = func
}

*/
/*predicate func_42(Variable vscratch_361, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_42.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
}

*/
/*predicate func_44(Function func, SwitchCase target_44) {
		target_44.toString() = "default: "
		and target_44.getEnclosingFunction() = func
}

*/
/*predicate func_45(Variable vscratch_361, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_45.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
}

*/
/*predicate func_48(Variable vattnum_382, Variable vscratch_361, ExprStmt target_48) {
		target_48.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="attnum"
		and target_48.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_48.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_48.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_48.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattnum_382
		and target_48.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

*/
/*predicate func_49(Variable vtle_380, Variable vscratch_361, ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_49.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_49.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_49.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_49.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_49.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_49.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

*/
/*predicate func_50(Variable vstate_360, Variable vscratch_361, ExprStmt target_50) {
		target_50.getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_50.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and target_50.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_361
}

*/
/*predicate func_51(Variable vtle_380, Variable vstate_360, ExprStmt target_51) {
		target_51.getExpr().(FunctionCall).getTarget().hasName("ExecInitExprRec")
		and target_51.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_51.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_51.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_360
		and target_51.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resvalue"
		and target_51.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
		and target_51.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resnull"
		and target_51.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_360
}

*/
/*predicate func_52(Variable vtle_380, Variable vscratch_361, IfStmt target_52) {
		target_52.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_typlen")
		and target_52.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_52.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_52.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_52.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_52.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_52.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_52.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_52.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
}

*/
/*predicate func_53(Variable vtle_380, Variable vscratch_361, ExprStmt target_53) {
		target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_tmp"
		and target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
		and target_53.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_53.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_380
		and target_53.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

*/
/*predicate func_54(Variable vstate_360, Variable vscratch_361, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_54.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and target_54.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_361
}

*/
predicate func_55(Variable vscratch_361, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_55.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_361
}

predicate func_56(Variable vstate_360, Variable vscratch_361, ExprStmt target_56) {
		target_56.getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_56.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
		and target_56.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_361
}

predicate func_57(Variable vstate_360, ExprStmt target_57) {
		target_57.getExpr().(FunctionCall).getTarget().hasName("ExecReadyExpr")
		and target_57.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_360
}

predicate func_58(Variable vprojInfo_359, VariableAccess target_58) {
		target_58.getTarget()=vprojInfo_359
}

predicate func_59(Variable vattnum_382, Parameter vinputDesc_357, RelationalOperation target_59) {
		 (target_59 instanceof GEExpr or target_59 instanceof LEExpr)
		and target_59.getLesserOperand().(VariableAccess).getTarget()=vattnum_382
		and target_59.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_59.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinputDesc_357
}

predicate func_60(ExprStmt target_60) {
		target_60.getExpr() instanceof AssignExpr
}

predicate func_61(LogicalAndExpr target_61) {
		target_61.getAnOperand() instanceof LogicalAndExpr
		and target_61.getAnOperand() instanceof RelationalOperation
}

predicate func_62(LogicalAndExpr target_62) {
		target_62.getAnOperand() instanceof NotExpr
		and target_62.getAnOperand() instanceof EqualityOperation
}

from Function func, Variable vlc_362, Variable vlc__state_378, Variable vtle_380, Variable vvariable_381, Variable vattnum_382, Variable visSafeVar_383, Variable vattr_405, Parameter vtargetList_353, Parameter vecontext_354, Parameter vslot_355, Parameter vparent_356, Parameter vinputDesc_357, Variable vprojInfo_359, Variable v_result_359, Variable vCurrentMemoryContext, Variable vstate_360, Variable vscratch_361, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, DeclStmt target_7, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, DeclStmt target_13, DeclStmt target_14, DeclStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, ForStmt target_24, IfStmt target_36, ExprStmt target_55, ExprStmt target_56, ExprStmt target_57, VariableAccess target_58, RelationalOperation target_59, ExprStmt target_60, LogicalAndExpr target_61, LogicalAndExpr target_62
where
not func_0(vtargetList_353, vecontext_354, vslot_355, vparent_356, vinputDesc_357, target_23, target_59)
and func_2(vecontext_354, vprojInfo_359, target_2)
and func_3(vtargetList_353, vstate_360, target_3)
and func_4(vparent_356, vstate_360, target_4)
and func_5(vslot_355, vstate_360, target_5)
and func_6(vinputDesc_357, target_60, target_6)
and func_7(func, target_7)
and func_9(func, target_9)
and func_10(v_result_359, vCurrentMemoryContext, target_10)
and func_11(v_result_359, target_11)
and func_12(v_result_359, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and func_15(func, target_15)
and func_16(vecontext_354, vprojInfo_359, func, target_16)
and func_17(vprojInfo_359, func, target_17)
and func_18(vprojInfo_359, vstate_360, func, target_18)
and func_19(vtargetList_353, vstate_360, func, target_19)
and func_20(vparent_356, vstate_360, func, target_20)
and func_21(vstate_360, func, target_21)
and func_22(vslot_355, vstate_360, func, target_22)
and func_23(vtargetList_353, vstate_360, func, target_23)
and func_24(vlc_362, vlc__state_378, vvariable_381, vattnum_382, visSafeVar_383, vinputDesc_357, vstate_360, func, target_24)
and func_36(vtle_380, vvariable_381, vattnum_382, visSafeVar_383, vstate_360, vscratch_361, target_36)
and func_55(vscratch_361, target_55)
and func_56(vstate_360, vscratch_361, target_56)
and func_57(vstate_360, target_57)
and func_58(vprojInfo_359, target_58)
and func_59(vattnum_382, vinputDesc_357, target_59)
and func_60(target_60)
and func_61(target_61)
and func_62(target_62)
and vlc_362.getType().hasName("ListCell *")
and vlc__state_378.getType().hasName("ForEachState")
and vtle_380.getType().hasName("TargetEntry *")
and vvariable_381.getType().hasName("Var *")
and vattnum_382.getType().hasName("AttrNumber")
and visSafeVar_383.getType().hasName("bool")
and vattr_405.getType().hasName("Form_pg_attribute")
and vtargetList_353.getType().hasName("List *")
and vecontext_354.getType().hasName("ExprContext *")
and vslot_355.getType().hasName("TupleTableSlot *")
and vparent_356.getType().hasName("PlanState *")
and vinputDesc_357.getType().hasName("TupleDesc")
and vprojInfo_359.getType().hasName("ProjectionInfo *")
and v_result_359.getType().hasName("Node *")
and vCurrentMemoryContext.getType().hasName("MemoryContext")
and vstate_360.getType().hasName("ExprState *")
and vscratch_361.getType().hasName("ExprEvalStep")
and vlc_362.(LocalVariable).getFunction() = func
and vlc__state_378.(LocalVariable).getFunction() = func
and vtle_380.(LocalVariable).getFunction() = func
and vvariable_381.(LocalVariable).getFunction() = func
and vattnum_382.(LocalVariable).getFunction() = func
and visSafeVar_383.(LocalVariable).getFunction() = func
and vattr_405.(LocalVariable).getFunction() = func
and vtargetList_353.getFunction() = func
and vecontext_354.getFunction() = func
and vslot_355.getFunction() = func
and vparent_356.getFunction() = func
and vinputDesc_357.getFunction() = func
and vprojInfo_359.(LocalVariable).getFunction() = func
and v_result_359.(LocalVariable).getFunction() = func
and not vCurrentMemoryContext.getParentScope+() = func
and vstate_360.(LocalVariable).getFunction() = func
and vscratch_361.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
