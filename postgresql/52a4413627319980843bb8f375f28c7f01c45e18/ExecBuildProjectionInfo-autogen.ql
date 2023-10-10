/**
 * @name postgresql-52a4413627319980843bb8f375f28c7f01c45e18-ExecBuildProjectionInfo
 * @id cpp/postgresql/52a4413627319980843bb8f375f28c7f01c45e18/ExecBuildProjectionInfo
 * @description postgresql-52a4413627319980843bb8f375f28c7f01c45e18-src/backend/executor/execExpr.c-ExecBuildProjectionInfo CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtargetList_301, Parameter vecontext_302, Parameter vslot_303, Parameter vparent_304, Parameter vinputDesc_305, ExprStmt target_21, RelationalOperation target_57) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ExecBuildProjectionInfoExt")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtargetList_301
		and target_0.getArgument(1).(VariableAccess).getTarget()=vecontext_302
		and target_0.getArgument(2).(VariableAccess).getTarget()=vslot_303
		and target_0.getArgument(3) instanceof Literal
		and target_0.getArgument(4).(VariableAccess).getTarget()=vparent_304
		and target_0.getArgument(5).(VariableAccess).getTarget()=vinputDesc_305
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(5).(VariableAccess).getLocation().isBefore(target_57.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtargetList_301, VariableAccess target_1) {
		target_1.getTarget()=vtargetList_301
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Parameter vecontext_302, Variable vprojInfo_307, VariableAccess target_3) {
		target_3.getTarget()=vecontext_302
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pi_exprContext"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_307
}

predicate func_4(Parameter vslot_303, Variable vstate_308, VariableAccess target_4) {
		target_4.getTarget()=vslot_303
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resultslot"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_308
}

predicate func_5(Parameter vinputDesc_305, ExprStmt target_58, VariableAccess target_5) {
		target_5.getTarget()=vinputDesc_305
		and target_5.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_58
}

predicate func_6(Parameter vparent_304, VariableAccess target_6) {
		target_6.getTarget()=vparent_304
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_7(Function func, DeclStmt target_7) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_9(Function func, ExprStmt target_9) {
		target_9.getExpr() instanceof Literal
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Variable v_result_307, Variable vCurrentMemoryContext, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v_result_307
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("MemoryContextAllocZeroAligned")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="104"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("MemoryContextAllocZero")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vCurrentMemoryContext
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="104"
}

predicate func_11(Variable v_result_307, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=v_result_307
}

predicate func_12(Variable v_result_307, ExprStmt target_12) {
		target_12.getExpr().(VariableAccess).getTarget()=v_result_307
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

predicate func_16(Parameter vecontext_302, Variable vprojInfo_307, Function func, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pi_exprContext"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_307
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vecontext_302
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Variable vprojInfo_307, Function func, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="tag"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_307
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Variable vprojInfo_307, Variable vstate_308, Function func, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstate_308
		and target_18.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_18.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprojInfo_307
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

predicate func_19(Parameter vtargetList_301, Variable vstate_308, Function func, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_308
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtargetList_301
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19
}

predicate func_20(Parameter vslot_303, Variable vstate_308, Function func, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resultslot"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_308
		and target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vslot_303
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Parameter vtargetList_301, Variable vstate_308, Function func, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("ExecInitExprSlots")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtargetList_301
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Variable vlc_310, Variable vvariable_326, Variable vattnum_327, Variable visSafeVar_328, Parameter vtargetList_301, Parameter vparent_304, Parameter vinputDesc_305, Variable vstate_308, Function func, ForStmt target_22) {
		target_22.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlc_310
		and target_22.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_head")
		and target_22.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtargetList_301
		and target_22.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlc_310
		and target_22.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getUpdate().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlc_310
		and target_22.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_22.getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlc_310
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="expr"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvariable_326
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_327
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinputDesc_305
		and target_22.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(VariableAccess).getTarget()=visSafeVar_328
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="varno"
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="attnum"
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecInitExprRec")
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparent_304
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstate_308
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_typlen")
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_22.getStmt().(BlockStmt).getStmt(5).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
}

/*predicate func_27(Variable vtle_325, Variable vvariable_326, Variable vattnum_327, Variable visSafeVar_328, Parameter vinputDesc_305, IfStmt target_27) {
		target_27.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="expr"
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="expr"
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_27.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvariable_326
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_27.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_27.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_327
		and target_27.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_27.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_326
		and target_27.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinputDesc_305
		and target_27.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_27.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_328
		and target_27.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_27.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vattnum_327
		and target_27.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_27.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinputDesc_305
}

*/
/*predicate func_28(Variable vtle_325, Variable vvariable_326, LogicalAndExpr target_59, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvariable_326
		and target_28.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="expr"
		and target_28.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_28.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

*/
/*predicate func_29(Variable vvariable_326, Variable vattnum_327, LogicalAndExpr target_59, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_327
		and target_29.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="varattno"
		and target_29.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_326
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

*/
/*predicate func_30(Variable vattnum_327, Variable visSafeVar_328, Parameter vinputDesc_305, LogicalAndExpr target_59, IfStmt target_30) {
		target_30.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinputDesc_305
		and target_30.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_328
		and target_30.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_30.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vattnum_327
		and target_30.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_30.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinputDesc_305
		and target_30.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="attisdropped"
		and target_30.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vartype"
		and target_30.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="atttypid"
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

*/
/*predicate func_31(RelationalOperation target_57, Function func, DeclStmt target_31) {
		target_31.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
		and target_31.getEnclosingFunction() = func
}

*/
/*predicate func_32(Variable vvariable_326, Variable visSafeVar_328, Variable vattr_350, RelationalOperation target_57, IfStmt target_32) {
		target_32.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="attisdropped"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_350
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vartype"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_326
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="atttypid"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_350
		and target_32.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_328
		and target_32.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_32.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
}

*/
/*predicate func_33(Variable visSafeVar_328, LogicalAndExpr target_60, ExprStmt target_58, IfStmt target_34, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=visSafeVar_328
		and target_33.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_60
		and target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_34.getCondition().(VariableAccess).getLocation())
}

*/
predicate func_34(Variable vtle_325, Variable vvariable_326, Variable vattnum_327, Variable visSafeVar_328, Parameter vparent_304, Variable vstate_308, Variable vscratch_309, IfStmt target_34) {
		target_34.getCondition().(VariableAccess).getTarget()=visSafeVar_328
		and target_34.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="varno"
		and target_34.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_326
		and target_34.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="65000"
		and target_34.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="65001"
		and target_34.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(6).(SwitchCase).toString() = "default: "
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="attnum"
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattnum_327
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_34.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_34.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_34.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_34.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_34.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_34.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_34.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_34.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and target_34.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_309
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecInitExprRec")
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparent_304
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstate_308
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resvalue"
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_308
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resnull"
		and target_34.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_308
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_typlen")
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_34.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_34.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_34.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_tmp"
		and target_34.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_34.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_34.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_34.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_34.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_34.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and target_34.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_309
}

/*predicate func_35(Variable vvariable_326, Variable vscratch_309, SwitchStmt target_35) {
		target_35.getExpr().(PointerFieldAccess).getTarget().getName()="varno"
		and target_35.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariable_326
		and target_35.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="65000"
		and target_35.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_35.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_35.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="65001"
		and target_35.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_35.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_35.getStmt().(BlockStmt).getStmt(6).(SwitchCase).toString() = "default: "
		and target_35.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_35.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
}

*/
/*predicate func_36(Function func, SwitchCase target_36) {
		target_36.getExpr().(Literal).getValue()="65000"
		and target_36.getEnclosingFunction() = func
}

*/
/*predicate func_37(Variable vscratch_309, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_37.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
}

*/
/*predicate func_39(Function func, SwitchCase target_39) {
		target_39.getExpr().(Literal).getValue()="65001"
		and target_39.getEnclosingFunction() = func
}

*/
/*predicate func_40(Variable vscratch_309, ExprStmt target_40) {
		target_40.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_40.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
}

*/
/*predicate func_42(Function func, SwitchCase target_42) {
		target_42.toString() = "default: "
		and target_42.getEnclosingFunction() = func
}

*/
/*predicate func_43(Variable vscratch_309, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_43.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
}

*/
/*predicate func_46(Variable vattnum_327, Variable vscratch_309, ExprStmt target_46) {
		target_46.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="attnum"
		and target_46.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_46.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_46.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_46.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattnum_327
		and target_46.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

*/
/*predicate func_47(Variable vtle_325, Variable vscratch_309, ExprStmt target_47) {
		target_47.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_47.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_var"
		and target_47.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_47.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_47.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_47.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_47.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

*/
/*predicate func_48(Variable vstate_308, Variable vscratch_309, ExprStmt target_48) {
		target_48.getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_48.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and target_48.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_309
}

*/
/*predicate func_49(Variable vtle_325, Parameter vparent_304, Variable vstate_308, ExprStmt target_49) {
		target_49.getExpr().(FunctionCall).getTarget().hasName("ExecInitExprRec")
		and target_49.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_49.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_49.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparent_304
		and target_49.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstate_308
		and target_49.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resvalue"
		and target_49.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_308
		and target_49.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="resnull"
		and target_49.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_308
}

*/
/*predicate func_50(Variable vtle_325, Variable vscratch_309, IfStmt target_50) {
		target_50.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_typlen")
		and target_50.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_50.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="expr"
		and target_50.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_50.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_50.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_50.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_50.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
}

*/
/*predicate func_51(Variable vtle_325, Variable vscratch_309, ExprStmt target_51) {
		target_51.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="resultnum"
		and target_51.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="assign_tmp"
		and target_51.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_51.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
		and target_51.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_51.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtle_325
		and target_51.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

*/
/*predicate func_52(Variable vstate_308, Variable vscratch_309, ExprStmt target_52) {
		target_52.getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_52.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and target_52.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_309
}

*/
predicate func_53(Variable vscratch_309, ExprStmt target_53) {
		target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="opcode"
		and target_53.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vscratch_309
}

predicate func_54(Variable vstate_308, Variable vscratch_309, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("ExprEvalPushStep")
		and target_54.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
		and target_54.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vscratch_309
}

predicate func_55(Variable vstate_308, ExprStmt target_55) {
		target_55.getExpr().(FunctionCall).getTarget().hasName("ExecReadyExpr")
		and target_55.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_308
}

predicate func_56(Variable vprojInfo_307, VariableAccess target_56) {
		target_56.getTarget()=vprojInfo_307
}

predicate func_57(Variable vattnum_327, Parameter vinputDesc_305, RelationalOperation target_57) {
		 (target_57 instanceof GEExpr or target_57 instanceof LEExpr)
		and target_57.getLesserOperand().(VariableAccess).getTarget()=vattnum_327
		and target_57.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_57.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinputDesc_305
}

predicate func_58(ExprStmt target_58) {
		target_58.getExpr() instanceof AssignExpr
}

predicate func_59(LogicalAndExpr target_59) {
		target_59.getAnOperand() instanceof LogicalAndExpr
		and target_59.getAnOperand() instanceof RelationalOperation
}

predicate func_60(LogicalAndExpr target_60) {
		target_60.getAnOperand() instanceof NotExpr
		and target_60.getAnOperand() instanceof EqualityOperation
}

from Function func, Variable vlc_310, Variable vtle_325, Variable vvariable_326, Variable vattnum_327, Variable visSafeVar_328, Variable vattr_350, Parameter vtargetList_301, Parameter vecontext_302, Parameter vslot_303, Parameter vparent_304, Parameter vinputDesc_305, Variable vprojInfo_307, Variable v_result_307, Variable vCurrentMemoryContext, Variable vstate_308, Variable vscratch_309, VariableAccess target_1, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, DeclStmt target_7, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, DeclStmt target_13, DeclStmt target_14, DeclStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, ForStmt target_22, IfStmt target_34, ExprStmt target_53, ExprStmt target_54, ExprStmt target_55, VariableAccess target_56, RelationalOperation target_57, ExprStmt target_58, LogicalAndExpr target_59, LogicalAndExpr target_60
where
not func_0(vtargetList_301, vecontext_302, vslot_303, vparent_304, vinputDesc_305, target_21, target_57)
and func_1(vtargetList_301, target_1)
and func_3(vecontext_302, vprojInfo_307, target_3)
and func_4(vslot_303, vstate_308, target_4)
and func_5(vinputDesc_305, target_58, target_5)
and func_6(vparent_304, target_6)
and func_7(func, target_7)
and func_9(func, target_9)
and func_10(v_result_307, vCurrentMemoryContext, target_10)
and func_11(v_result_307, target_11)
and func_12(v_result_307, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and func_15(func, target_15)
and func_16(vecontext_302, vprojInfo_307, func, target_16)
and func_17(vprojInfo_307, func, target_17)
and func_18(vprojInfo_307, vstate_308, func, target_18)
and func_19(vtargetList_301, vstate_308, func, target_19)
and func_20(vslot_303, vstate_308, func, target_20)
and func_21(vtargetList_301, vstate_308, func, target_21)
and func_22(vlc_310, vvariable_326, vattnum_327, visSafeVar_328, vtargetList_301, vparent_304, vinputDesc_305, vstate_308, func, target_22)
and func_34(vtle_325, vvariable_326, vattnum_327, visSafeVar_328, vparent_304, vstate_308, vscratch_309, target_34)
and func_53(vscratch_309, target_53)
and func_54(vstate_308, vscratch_309, target_54)
and func_55(vstate_308, target_55)
and func_56(vprojInfo_307, target_56)
and func_57(vattnum_327, vinputDesc_305, target_57)
and func_58(target_58)
and func_59(target_59)
and func_60(target_60)
and vlc_310.getType().hasName("ListCell *")
and vtle_325.getType().hasName("TargetEntry *")
and vvariable_326.getType().hasName("Var *")
and vattnum_327.getType().hasName("AttrNumber")
and visSafeVar_328.getType().hasName("bool")
and vattr_350.getType().hasName("Form_pg_attribute")
and vtargetList_301.getType().hasName("List *")
and vecontext_302.getType().hasName("ExprContext *")
and vslot_303.getType().hasName("TupleTableSlot *")
and vparent_304.getType().hasName("PlanState *")
and vinputDesc_305.getType().hasName("TupleDesc")
and vprojInfo_307.getType().hasName("ProjectionInfo *")
and v_result_307.getType().hasName("Node *")
and vCurrentMemoryContext.getType().hasName("MemoryContext")
and vstate_308.getType().hasName("ExprState *")
and vscratch_309.getType().hasName("ExprEvalStep")
and vlc_310.(LocalVariable).getFunction() = func
and vtle_325.(LocalVariable).getFunction() = func
and vvariable_326.(LocalVariable).getFunction() = func
and vattnum_327.(LocalVariable).getFunction() = func
and visSafeVar_328.(LocalVariable).getFunction() = func
and vattr_350.(LocalVariable).getFunction() = func
and vtargetList_301.getFunction() = func
and vecontext_302.getFunction() = func
and vslot_303.getFunction() = func
and vparent_304.getFunction() = func
and vinputDesc_305.getFunction() = func
and vprojInfo_307.(LocalVariable).getFunction() = func
and v_result_307.(LocalVariable).getFunction() = func
and not vCurrentMemoryContext.getParentScope+() = func
and vstate_308.(LocalVariable).getFunction() = func
and vscratch_309.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
