/**
 * @name freerdp-3a06ce058f690b7fc1edad2f352c453376c2ebfe-rfx_process_message_tileset
 * @id cpp/freerdp/3a06ce058f690b7fc1edad2f352c453376c2ebfe/rfx-process-message-tileset
 * @description freerdp-3a06ce058f690b7fc1edad2f352c453376c2ebfe-libfreerdp/codec/rfx.c-rfx_process_message_tileset CVE-2020-11043
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_750, FunctionCall target_0) {
		target_0.getTarget().hasName("Stream_GetPosition")
		and not target_0.getTarget().hasName("Stream_GetRemainingLength")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_750
}

predicate func_1(Parameter vs_750, Variable vtile_757, FunctionCall target_1) {
		target_1.getTarget().hasName("Stream_Seek")
		and not target_1.getTarget().hasName("Stream_StaticInit")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="YLen"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
}

predicate func_3(Function func) {
	exists(AddressOfExpr target_3 |
		target_3.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(AddressOfExpr target_4 |
		target_4.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(AddressOfExpr target_5 |
		target_5.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vs_750) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2")
}

predicate func_7(Function func) {
	exists(AddressOfExpr target_7 |
		target_7.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(AddressOfExpr target_8 |
		target_8.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(AddressOfExpr target_9 |
		target_9.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(AddressOfExpr target_10 |
		target_10.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Parameter vs_750) {
	exists(AddressOfExpr target_11 |
		target_11.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4")
}

predicate func_12(Parameter vs_750, Variable vblockLen_761, BlockStmt target_102, ExprStmt target_103, ExprStmt target_105) {
	exists(NotExpr target_12 |
		target_12.getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_12.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_12.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vblockLen_761
		and target_12.getParent().(IfStmt).getThen()=target_102
		and target_103.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_105.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getLocation().isBefore(target_12.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_13(Variable vrc_753, ExprStmt target_106) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(VariableAccess).getTarget()=vrc_753
		and target_13.getRValue().(Literal).getValue()="0"
		and target_106.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getLValue().(VariableAccess).getLocation()))
}

predicate func_14(RelationalOperation target_107, Function func) {
	exists(BreakStmt target_14 |
		target_14.toString() = "break;"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_107
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Variable vblockLen_761, ExprStmt target_108, ExprStmt target_109, RelationalOperation target_107) {
	exists(LogicalOrExpr target_15 |
		target_15.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vblockLen_761
		and target_15.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="19"
		and target_15.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_15.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("wStream")
		and target_15.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof SubExpr
		and target_15.getParent().(IfStmt).getThen()=target_108
		and target_109.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_17(BlockStmt target_102, Function func) {
	exists(AddExpr target_17 |
		target_17.getValue()="19"
		and target_17.getParent().(LTExpr).getLesserOperand() instanceof FunctionCall
		and target_17.getParent().(LTExpr).getGreaterOperand() instanceof SubExpr
		and target_17.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_102
		and target_17.getEnclosingFunction() = func)
}

*/
/*predicate func_18(Function func) {
	exists(AddressOfExpr target_18 |
		target_18.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_18.getParent().(FunctionCall).getParent().(SubExpr).getLeftOperand() instanceof FunctionCall
		and target_18.getEnclosingFunction() = func)
}

*/
predicate func_19(Function func) {
	exists(AddressOfExpr target_19 |
		target_19.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Parameter vs_750) {
	exists(AddressOfExpr target_20 |
		target_20.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_20.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1")
}

predicate func_21(Function func) {
	exists(AddressOfExpr target_21 |
		target_21.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(Parameter vs_750) {
	exists(AddressOfExpr target_22 |
		target_22.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_22.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1")
}

predicate func_23(Function func) {
	exists(AddressOfExpr target_23 |
		target_23.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_23.getEnclosingFunction() = func)
}

predicate func_24(Parameter vs_750) {
	exists(AddressOfExpr target_24 |
		target_24.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_24.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1")
}

predicate func_25(Function func) {
	exists(AddressOfExpr target_25 |
		target_25.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_25.getEnclosingFunction() = func)
}

predicate func_26(Function func) {
	exists(AddressOfExpr target_26 |
		target_26.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_26.getEnclosingFunction() = func)
}

predicate func_27(Parameter vs_750) {
	exists(AddressOfExpr target_27 |
		target_27.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2")
}

predicate func_28(Function func) {
	exists(AddressOfExpr target_28 |
		target_28.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_28.getEnclosingFunction() = func)
}

predicate func_29(Function func) {
	exists(AddressOfExpr target_29 |
		target_29.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_29.getEnclosingFunction() = func)
}

predicate func_30(Parameter vs_750) {
	exists(AddressOfExpr target_30 |
		target_30.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2")
}

predicate func_31(Function func) {
	exists(AddressOfExpr target_31 |
		target_31.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_31.getEnclosingFunction() = func)
}

predicate func_32(Function func) {
	exists(AddressOfExpr target_32 |
		target_32.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_32.getEnclosingFunction() = func)
}

predicate func_33(Parameter vs_750) {
	exists(AddressOfExpr target_33 |
		target_33.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_33.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2")
}

predicate func_34(Function func) {
	exists(AddressOfExpr target_34 |
		target_34.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_34.getEnclosingFunction() = func)
}

predicate func_35(Function func) {
	exists(AddressOfExpr target_35 |
		target_35.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_35.getEnclosingFunction() = func)
}

predicate func_36(Parameter vs_750) {
	exists(AddressOfExpr target_36 |
		target_36.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_36.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2")
}

predicate func_37(Function func) {
	exists(AddressOfExpr target_37 |
		target_37.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_37.getEnclosingFunction() = func)
}

predicate func_38(Function func) {
	exists(AddressOfExpr target_38 |
		target_38.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_38.getEnclosingFunction() = func)
}

predicate func_39(Function func) {
	exists(IfStmt target_39 |
		target_39.getCondition() instanceof Literal
		and target_39.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_39.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("wStream")
		and target_39.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_39.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
		and target_39.getEnclosingFunction() = func)
}

/*predicate func_40(Parameter vs_750) {
	exists(AddressOfExpr target_40 |
		target_40.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_40.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_40.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_40.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_40.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2")
}

*/
predicate func_41(Parameter vs_750) {
	exists(AddressOfExpr target_41 |
		target_41.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_41.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_Pointer")
		and target_41.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750)
}

predicate func_42(Variable vrc_753, Variable vtile_757, ExprStmt target_110, ExprStmt target_111) {
	exists(IfStmt target_42 |
		target_42.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_42.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("wStream")
		and target_42.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="YLen"
		and target_42.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_42.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_753
		and target_42.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_42.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_110.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_42.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_42.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_111.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_44(Parameter vs_750) {
	exists(AddressOfExpr target_44 |
		target_44.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_44.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_Pointer")
		and target_44.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750)
}

predicate func_45(Variable vrc_753, Variable vtile_757, ExprStmt target_111, ExprStmt target_112) {
	exists(IfStmt target_45 |
		target_45.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_45.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("wStream")
		and target_45.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="CbLen"
		and target_45.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_45.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_753
		and target_45.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_45.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_111.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_45.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_45.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_112.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_47(Function func) {
	exists(FunctionCall target_47 |
		target_47.getTarget().hasName("Stream_Pointer")
		and target_47.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("wStream")
		and target_47.getEnclosingFunction() = func)
}

predicate func_48(Variable vrc_753, Variable vtile_757, ExprStmt target_113, ReturnStmt target_114, ExprStmt target_112, ExprStmt target_115) {
	exists(IfStmt target_48 |
		target_48.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_48.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("wStream")
		and target_48.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="CrLen"
		and target_48.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_48.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_753
		and target_48.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_48.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_113.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_48.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_48.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_114.getExpr().(VariableAccess).getLocation())
		and target_112.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_48.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_48.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_115.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_49(Variable vrc_753, ExprStmt target_113, ReturnStmt target_114) {
	exists(AssignExpr target_49 |
		target_49.getLValue().(VariableAccess).getTarget()=vrc_753
		and target_49.getRValue().(Literal).getValue()="0"
		and target_113.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_49.getLValue().(VariableAccess).getLocation())
		and target_49.getLValue().(VariableAccess).getLocation().isBefore(target_114.getExpr().(VariableAccess).getLocation()))
}

*/
predicate func_50(Parameter vs_750, Variable vblockLen_761, BlockStmt target_102, SubExpr target_50) {
		target_50.getLeftOperand().(VariableAccess).getTarget()=vblockLen_761
		and target_50.getRightOperand().(Literal).getValue()="6"
		and target_50.getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_50.getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_50.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_102
}

/*predicate func_51(Parameter vs_750, FunctionCall target_51) {
		target_51.getTarget().hasName("Stream_GetRemainingLength")
		and target_51.getArgument(0).(VariableAccess).getTarget()=vs_750
}

*/
predicate func_52(Parameter vs_750, FunctionCall target_52) {
		target_52.getTarget().hasName("Stream_Pointer")
		and target_52.getArgument(0).(VariableAccess).getTarget()=vs_750
}

predicate func_53(Variable vtile_757, PointerFieldAccess target_53) {
		target_53.getTarget().getName()="YLen"
		and target_53.getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_53.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_54(Variable vtile_757, PointerFieldAccess target_54) {
		target_54.getTarget().getName()="CbLen"
		and target_54.getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_54.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_55(Variable vtile_757, PointerFieldAccess target_55) {
		target_55.getTarget().getName()="CrLen"
		and target_55.getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_55.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_56(Parameter vs_750, VariableAccess target_56) {
		target_56.getTarget()=vs_750
		and target_56.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_56.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_56.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_66(Variable vblockLen_761, VariableAccess target_66) {
		target_66.getTarget()=vblockLen_761
}

predicate func_68(Parameter vs_750, RelationalOperation target_116, VariableAccess target_68) {
		target_68.getTarget()=vs_750
		and target_116.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_68.getLocation())
}

predicate func_69(Parameter vs_750, VariableAccess target_69) {
		target_69.getTarget()=vs_750
}

predicate func_70(Parameter vs_750, ExprStmt target_117, VariableAccess target_70) {
		target_70.getTarget()=vs_750
		and target_117.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_70.getLocation())
}

predicate func_71(Parameter vs_750, VariableAccess target_71) {
		target_71.getTarget()=vs_750
}

predicate func_72(Parameter vs_750, VariableAccess target_72) {
		target_72.getTarget()=vs_750
}

predicate func_73(Parameter vs_750, VariableAccess target_73) {
		target_73.getTarget()=vs_750
}

predicate func_74(Parameter vs_750, RelationalOperation target_107, VariableAccess target_74) {
		target_74.getTarget()=vs_750
		and target_74.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_74.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_74.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
}

predicate func_75(Variable vpos_755, Variable vblockLen_761, AssignExpr target_75) {
		target_75.getLValue().(VariableAccess).getTarget()=vpos_755
		and target_75.getRValue().(AddExpr).getAnOperand().(SubExpr).getLeftOperand() instanceof FunctionCall
		and target_75.getRValue().(AddExpr).getAnOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_75.getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vblockLen_761
}

predicate func_76(Parameter vs_750, VariableAccess target_76) {
		target_76.getTarget()=vs_750
}

predicate func_77(Parameter vs_750, ExprStmt target_119, VariableAccess target_77) {
		target_77.getTarget()=vs_750
		and target_77.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_77.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_77.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
		and target_77.getLocation().isBefore(target_119.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_78(Parameter vs_750, ExprStmt target_108, VariableAccess target_78) {
		target_78.getTarget()=vs_750
		and target_108.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_78.getLocation())
}

predicate func_79(Parameter vs_750, ExprStmt target_120, VariableAccess target_79) {
		target_79.getTarget()=vs_750
		and target_79.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_79.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_79.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
		and target_79.getLocation().isBefore(target_120.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_80(Parameter vs_750, ExprStmt target_121, VariableAccess target_80) {
		target_80.getTarget()=vs_750
		and target_121.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_80.getLocation())
}

predicate func_81(Parameter vs_750, ExprStmt target_122, VariableAccess target_81) {
		target_81.getTarget()=vs_750
		and target_81.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_81.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_81.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
		and target_81.getLocation().isBefore(target_122.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_82(Parameter vs_750, ExprStmt target_123, VariableAccess target_82) {
		target_82.getTarget()=vs_750
		and target_123.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_82.getLocation())
}

predicate func_83(Parameter vs_750, VariableAccess target_83) {
		target_83.getTarget()=vs_750
}

predicate func_84(Parameter vs_750, ExprStmt target_124, VariableAccess target_84) {
		target_84.getTarget()=vs_750
		and target_84.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_84.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_84.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
		and target_84.getLocation().isBefore(target_124.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_85(Parameter vs_750, ExprStmt target_125, VariableAccess target_85) {
		target_85.getTarget()=vs_750
		and target_125.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_85.getLocation())
}

predicate func_86(Parameter vs_750, VariableAccess target_86) {
		target_86.getTarget()=vs_750
}

predicate func_87(Parameter vs_750, ExprStmt target_126, VariableAccess target_87) {
		target_87.getTarget()=vs_750
		and target_87.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_87.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_87.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
		and target_87.getLocation().isBefore(target_126.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_88(Parameter vs_750, ExprStmt target_127, VariableAccess target_88) {
		target_88.getTarget()=vs_750
		and target_127.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_88.getLocation())
}

predicate func_89(Parameter vs_750, VariableAccess target_89) {
		target_89.getTarget()=vs_750
}

predicate func_90(Parameter vs_750, ExprStmt target_128, VariableAccess target_90) {
		target_90.getTarget()=vs_750
		and target_90.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_90.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_90.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
		and target_90.getLocation().isBefore(target_128.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_91(Parameter vs_750, ExprStmt target_129, VariableAccess target_91) {
		target_91.getTarget()=vs_750
		and target_129.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_91.getLocation())
}

predicate func_92(Parameter vs_750, VariableAccess target_92) {
		target_92.getTarget()=vs_750
}

predicate func_93(Parameter vs_750, ExprStmt target_130, VariableAccess target_93) {
		target_93.getTarget()=vs_750
		and target_93.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_93.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_93.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
		and target_93.getLocation().isBefore(target_130.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_94(Parameter vs_750, ExprStmt target_131, VariableAccess target_94) {
		target_94.getTarget()=vs_750
		and target_131.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_94.getLocation())
}

predicate func_95(Parameter vs_750, VariableAccess target_95) {
		target_95.getTarget()=vs_750
}

predicate func_96(Parameter vs_750, ExprStmt target_110, VariableAccess target_96) {
		target_96.getTarget()=vs_750
		and target_96.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_96.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_96.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_97(Parameter vs_750, VariableAccess target_97) {
		target_97.getTarget()=vs_750
		and target_97.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_Pointer")
}

predicate func_98(Parameter vs_750, Variable vtile_757, FunctionCall target_98) {
		target_98.getTarget().hasName("Stream_Seek")
		and target_98.getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_98.getArgument(1).(PointerFieldAccess).getTarget().getName()="CbLen"
		and target_98.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
}

predicate func_99(Parameter vs_750, VariableAccess target_99) {
		target_99.getTarget()=vs_750
		and target_99.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_Pointer")
}

predicate func_100(Parameter vs_750, Variable vtile_757, FunctionCall target_100) {
		target_100.getTarget().hasName("Stream_Seek")
		and target_100.getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_100.getArgument(1).(PointerFieldAccess).getTarget().getName()="CrLen"
		and target_100.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
}

predicate func_101(Parameter vs_750, Variable vpos_755, FunctionCall target_101) {
		target_101.getTarget().hasName("Stream_SetPosition")
		and target_101.getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_101.getArgument(1).(VariableAccess).getTarget()=vpos_755
}

predicate func_102(Variable vrc_753, BlockStmt target_102) {
		target_102.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_102.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("WLog_Get")
		and target_102.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_102.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("WLog_IsLevelActive")
		and target_102.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_753
		and target_102.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_103(Parameter vs_750, ExprStmt target_103) {
		target_103.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_103.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
		and target_103.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_103.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_103.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_105(Variable vblockLen_761, ExprStmt target_105) {
		target_105.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_105.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_105.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_105.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_105.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_105.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="RfxMessageTileSet not enough bytes to read tile %d/%u with blocklen=%u"
		and target_105.getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="numTiles"
		and target_105.getExpr().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vblockLen_761
}

predicate func_106(Variable vrc_753, ExprStmt target_106) {
		target_106.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_753
		and target_106.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_107(RelationalOperation target_107) {
		 (target_107 instanceof GTExpr or target_107 instanceof LTExpr)
		and target_107.getLesserOperand() instanceof FunctionCall
		and target_107.getGreaterOperand() instanceof SubExpr
}

predicate func_108(Parameter vs_750, ExprStmt target_108) {
		target_108.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_108.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_108.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_108.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
}

predicate func_109(Variable vblockLen_761, ExprStmt target_109) {
		target_109.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vblockLen_761
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_109.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_110(Variable vtile_757, ExprStmt target_110) {
		target_110.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="YData"
		and target_110.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_110.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_111(Parameter vs_750, Variable vtile_757, ExprStmt target_111) {
		target_111.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CbData"
		and target_111.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_111.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_Pointer")
		and target_111.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
}

predicate func_112(Parameter vs_750, Variable vtile_757, ExprStmt target_112) {
		target_112.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CrData"
		and target_112.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_112.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_Pointer")
		and target_112.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
}

predicate func_113(Variable vrc_753, ExprStmt target_113) {
		target_113.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_753
		and target_113.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_114(Variable vrc_753, ReturnStmt target_114) {
		target_114.getExpr().(VariableAccess).getTarget()=vrc_753
}

predicate func_115(Variable vtile_757, ExprStmt target_115) {
		target_115.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="x"
		and target_115.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_115.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="xIdx"
		and target_115.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_115.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="64"
}

predicate func_116(Parameter vs_750, RelationalOperation target_116) {
		 (target_116 instanceof GTExpr or target_116 instanceof LTExpr)
		and target_116.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_116.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_116.getGreaterOperand().(Literal).getValue()="6"
}

predicate func_117(Parameter vs_750, ExprStmt target_117) {
		target_117.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_117.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_117.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_117.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_119(Parameter vs_750, Variable vtile_757, ExprStmt target_119) {
		target_119.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="quantIdxCb"
		and target_119.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_119.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_119.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
}

predicate func_120(Parameter vs_750, Variable vtile_757, ExprStmt target_120) {
		target_120.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="quantIdxCr"
		and target_120.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_120.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_120.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
}

predicate func_121(Parameter vs_750, ExprStmt target_121) {
		target_121.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_121.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_121.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_121.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
}

predicate func_122(Parameter vs_750, Variable vtile_757, ExprStmt target_122) {
		target_122.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="xIdx"
		and target_122.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_122.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_122.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
		and target_122.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_122.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_122.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_123(Parameter vs_750, ExprStmt target_123) {
		target_123.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_123.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_123.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_123.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
}

predicate func_124(Parameter vs_750, Variable vtile_757, ExprStmt target_124) {
		target_124.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="yIdx"
		and target_124.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_124.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_124.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
		and target_124.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_124.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_124.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_125(Parameter vs_750, ExprStmt target_125) {
		target_125.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_125.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_125.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_125.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_126(Parameter vs_750, Variable vtile_757, ExprStmt target_126) {
		target_126.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="YLen"
		and target_126.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_126.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_126.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
		and target_126.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_126.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_126.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_127(Parameter vs_750, ExprStmt target_127) {
		target_127.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_127.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_127.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_127.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_128(Parameter vs_750, Variable vtile_757, ExprStmt target_128) {
		target_128.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CbLen"
		and target_128.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_128.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_128.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
		and target_128.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_128.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_128.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_129(Parameter vs_750, ExprStmt target_129) {
		target_129.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_129.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_129.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_129.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_130(Parameter vs_750, Variable vtile_757, ExprStmt target_130) {
		target_130.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="CrLen"
		and target_130.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_757
		and target_130.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_130.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_750
		and target_130.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_130.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_130.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_131(Parameter vs_750, ExprStmt target_131) {
		target_131.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_131.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_750
		and target_131.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_131.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

from Function func, Parameter vs_750, Variable vrc_753, Variable vpos_755, Variable vtile_757, Variable vblockLen_761, FunctionCall target_0, FunctionCall target_1, SubExpr target_50, FunctionCall target_52, PointerFieldAccess target_53, PointerFieldAccess target_54, PointerFieldAccess target_55, VariableAccess target_56, VariableAccess target_66, VariableAccess target_68, VariableAccess target_69, VariableAccess target_70, VariableAccess target_71, VariableAccess target_72, VariableAccess target_73, VariableAccess target_74, AssignExpr target_75, VariableAccess target_76, VariableAccess target_77, VariableAccess target_78, VariableAccess target_79, VariableAccess target_80, VariableAccess target_81, VariableAccess target_82, VariableAccess target_83, VariableAccess target_84, VariableAccess target_85, VariableAccess target_86, VariableAccess target_87, VariableAccess target_88, VariableAccess target_89, VariableAccess target_90, VariableAccess target_91, VariableAccess target_92, VariableAccess target_93, VariableAccess target_94, VariableAccess target_95, VariableAccess target_96, VariableAccess target_97, FunctionCall target_98, VariableAccess target_99, FunctionCall target_100, FunctionCall target_101, BlockStmt target_102, ExprStmt target_103, ExprStmt target_105, ExprStmt target_106, RelationalOperation target_107, ExprStmt target_108, ExprStmt target_109, ExprStmt target_110, ExprStmt target_111, ExprStmt target_112, ExprStmt target_113, ReturnStmt target_114, ExprStmt target_115, RelationalOperation target_116, ExprStmt target_117, ExprStmt target_119, ExprStmt target_120, ExprStmt target_121, ExprStmt target_122, ExprStmt target_123, ExprStmt target_124, ExprStmt target_125, ExprStmt target_126, ExprStmt target_127, ExprStmt target_128, ExprStmt target_129, ExprStmt target_130, ExprStmt target_131
where
func_0(vs_750, target_0)
and func_1(vs_750, vtile_757, target_1)
and not func_3(func)
and not func_4(func)
and not func_5(func)
and not func_6(vs_750)
and not func_7(func)
and not func_8(func)
and not func_9(func)
and not func_10(func)
and not func_11(vs_750)
and not func_12(vs_750, vblockLen_761, target_102, target_103, target_105)
and not func_13(vrc_753, target_106)
and not func_14(target_107, func)
and not func_15(vblockLen_761, target_108, target_109, target_107)
and not func_19(func)
and not func_20(vs_750)
and not func_21(func)
and not func_22(vs_750)
and not func_23(func)
and not func_24(vs_750)
and not func_25(func)
and not func_26(func)
and not func_27(vs_750)
and not func_28(func)
and not func_29(func)
and not func_30(vs_750)
and not func_31(func)
and not func_32(func)
and not func_33(vs_750)
and not func_34(func)
and not func_35(func)
and not func_36(vs_750)
and not func_37(func)
and not func_38(func)
and not func_39(func)
and not func_41(vs_750)
and not func_42(vrc_753, vtile_757, target_110, target_111)
and not func_44(vs_750)
and not func_45(vrc_753, vtile_757, target_111, target_112)
and not func_47(func)
and not func_48(vrc_753, vtile_757, target_113, target_114, target_112, target_115)
and func_50(vs_750, vblockLen_761, target_102, target_50)
and func_52(vs_750, target_52)
and func_53(vtile_757, target_53)
and func_54(vtile_757, target_54)
and func_55(vtile_757, target_55)
and func_56(vs_750, target_56)
and func_66(vblockLen_761, target_66)
and func_68(vs_750, target_116, target_68)
and func_69(vs_750, target_69)
and func_70(vs_750, target_117, target_70)
and func_71(vs_750, target_71)
and func_72(vs_750, target_72)
and func_73(vs_750, target_73)
and func_74(vs_750, target_107, target_74)
and func_75(vpos_755, vblockLen_761, target_75)
and func_76(vs_750, target_76)
and func_77(vs_750, target_119, target_77)
and func_78(vs_750, target_108, target_78)
and func_79(vs_750, target_120, target_79)
and func_80(vs_750, target_121, target_80)
and func_81(vs_750, target_122, target_81)
and func_82(vs_750, target_123, target_82)
and func_83(vs_750, target_83)
and func_84(vs_750, target_124, target_84)
and func_85(vs_750, target_125, target_85)
and func_86(vs_750, target_86)
and func_87(vs_750, target_126, target_87)
and func_88(vs_750, target_127, target_88)
and func_89(vs_750, target_89)
and func_90(vs_750, target_128, target_90)
and func_91(vs_750, target_129, target_91)
and func_92(vs_750, target_92)
and func_93(vs_750, target_130, target_93)
and func_94(vs_750, target_131, target_94)
and func_95(vs_750, target_95)
and func_96(vs_750, target_110, target_96)
and func_97(vs_750, target_97)
and func_98(vs_750, vtile_757, target_98)
and func_99(vs_750, target_99)
and func_100(vs_750, vtile_757, target_100)
and func_101(vs_750, vpos_755, target_101)
and func_102(vrc_753, target_102)
and func_103(vs_750, target_103)
and func_105(vblockLen_761, target_105)
and func_106(vrc_753, target_106)
and func_107(target_107)
and func_108(vs_750, target_108)
and func_109(vblockLen_761, target_109)
and func_110(vtile_757, target_110)
and func_111(vs_750, vtile_757, target_111)
and func_112(vs_750, vtile_757, target_112)
and func_113(vrc_753, target_113)
and func_114(vrc_753, target_114)
and func_115(vtile_757, target_115)
and func_116(vs_750, target_116)
and func_117(vs_750, target_117)
and func_119(vs_750, vtile_757, target_119)
and func_120(vs_750, vtile_757, target_120)
and func_121(vs_750, target_121)
and func_122(vs_750, vtile_757, target_122)
and func_123(vs_750, target_123)
and func_124(vs_750, vtile_757, target_124)
and func_125(vs_750, target_125)
and func_126(vs_750, vtile_757, target_126)
and func_127(vs_750, target_127)
and func_128(vs_750, vtile_757, target_128)
and func_129(vs_750, target_129)
and func_130(vs_750, vtile_757, target_130)
and func_131(vs_750, target_131)
and vs_750.getType().hasName("wStream *")
and vrc_753.getType().hasName("BOOL")
and vpos_755.getType().hasName("size_t")
and vtile_757.getType().hasName("RFX_TILE *")
and vblockLen_761.getType().hasName("UINT32")
and vs_750.getParentScope+() = func
and vrc_753.getParentScope+() = func
and vpos_755.getParentScope+() = func
and vtile_757.getParentScope+() = func
and vblockLen_761.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
