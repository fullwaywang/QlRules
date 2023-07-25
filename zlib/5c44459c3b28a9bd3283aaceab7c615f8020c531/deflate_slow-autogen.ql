/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_slow
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflate-slow
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate.c-deflate_slow CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_0, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="last_lit"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_1(Parameter vs_0, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="l_buf"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_2(Parameter vs_0, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="last_lit"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_3(Parameter vs_0, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="last_lit"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_4(Parameter vs_0, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="lit_bufsize"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_5(Parameter vs_0, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="last_lit"
		and target_5.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_6(Parameter vs_0, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="l_buf"
		and target_6.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_7(Parameter vs_0, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="last_lit"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_8(Parameter vs_0, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="last_lit"
		and target_8.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_9(Parameter vs_0, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="lit_bufsize"
		and target_9.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_10(Parameter vs_0, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="last_lit"
		and target_10.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_11(Parameter vs_0, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="l_buf"
		and target_11.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_12(Parameter vs_0, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="last_lit"
		and target_12.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_13(Parameter vs_0, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="last_lit"
		and target_13.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_14(Function func, Literal target_14) {
		target_14.getValue()="1"
		and not target_14.getValue()="8"
		and target_14.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Function func, Literal target_15) {
		target_15.getValue()="1"
		and not target_15.getValue()="0"
		and target_15.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Function func, Literal target_16) {
		target_16.getValue()="1"
		and not target_16.getValue()="0"
		and target_16.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Parameter vs_0, Variable vdist_2005, SubExpr target_39) {
	exists(AssignExpr target_17 |
		target_17.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_17.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_17.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_17.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_17.getRValue().(VariableAccess).getTarget()=vdist_2005
		and target_39.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_18(Parameter vs_0, Variable vdist_2005, ArrayExpr target_40) {
	exists(AssignExpr target_18 |
		target_18.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_18.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_18.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_18.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_18.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_2005
		and target_18.getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_40.getArrayOffset().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_18.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_19(Parameter vs_0, ExprStmt target_41, ExprStmt target_42) {
	exists(AssignExpr target_19 |
		target_19.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_19.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_19.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_19.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_19.getRValue() instanceof Literal
		and target_41.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_20(Parameter vs_0) {
	exists(AssignExpr target_20 |
		target_20.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_20.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_20.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_20.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_20.getRValue() instanceof Literal)
}

predicate func_21(Parameter vs_0, ArrayExpr target_44) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_44.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_22(Parameter vs_0) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_22.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_22.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_23(Parameter vs_0, Variable vbflush_1944, ExprStmt target_45, IfStmt target_46) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_1944
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_45.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_46.getCondition().(VariableAccess).getLocation().isBefore(target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_24(Parameter vs_0, VariableAccess target_24) {
		target_24.getTarget()=vs_0
}

predicate func_25(Variable vdist_2005, VariableAccess target_25) {
		target_25.getTarget()=vdist_2005
		and target_25.getParent().(AssignExpr).getRValue() = target_25
		and target_25.getParent().(AssignExpr).getLValue() instanceof ArrayExpr
}

predicate func_26(Parameter vs_0, VariableAccess target_26) {
		target_26.getTarget()=vs_0
}

predicate func_28(Parameter vs_0, VariableAccess target_28) {
		target_28.getTarget()=vs_0
}

predicate func_30(Parameter vs_0, VariableAccess target_30) {
		target_30.getTarget()=vs_0
}

predicate func_31(Parameter vs_0, VariableAccess target_31) {
		target_31.getTarget()=vs_0
}

predicate func_32(Parameter vs_0, Variable vdist_2005, AssignExpr target_32) {
		target_32.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_32.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_32.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_32.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_32.getRValue().(VariableAccess).getTarget()=vdist_2005
}

predicate func_33(Parameter vs_0, ExprStmt target_47, SubExpr target_33) {
		target_33.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_33.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_33.getRightOperand() instanceof Literal
		and target_33.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_47.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_34(Parameter vs_0, AssignExpr target_34) {
		target_34.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_34.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_34.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_34.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_34.getRValue() instanceof Literal
}

predicate func_35(Parameter vs_0, ExprStmt target_45, SubExpr target_35) {
		target_35.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_35.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_35.getRightOperand() instanceof Literal
		and target_35.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_45.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_36(Parameter vs_0, AssignExpr target_36) {
		target_36.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_36.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_36.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_36.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_36.getRValue() instanceof Literal
}

predicate func_37(Parameter vs_0, PointerFieldAccess target_37) {
		target_37.getTarget().getName()="last_lit"
		and target_37.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_38(Parameter vs_0, ExprStmt target_48, SubExpr target_38) {
		target_38.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_38.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_38.getRightOperand() instanceof Literal
		and target_38.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_48.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_39(Parameter vs_0, SubExpr target_39) {
		target_39.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="strstart"
		and target_39.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_39.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_39.getRightOperand().(PointerFieldAccess).getTarget().getName()="prev_match"
		and target_39.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_40(Parameter vs_0, Variable vdist_2005, ArrayExpr target_40) {
		target_40.getArrayBase().(PointerFieldAccess).getTarget().getName()="dyn_dtree"
		and target_40.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_40.getArrayOffset().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdist_2005
		and target_40.getArrayOffset().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_40.getArrayOffset().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vdist_2005
		and target_40.getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="256"
		and target_40.getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_2005
		and target_40.getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
}

predicate func_41(Parameter vs_0, Variable vbflush_1944, ExprStmt target_41) {
		target_41.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_1944
		and target_41.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_41.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_41.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand() instanceof SubExpr
}

predicate func_42(Parameter vs_0, Variable vbflush_1944, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_1944
		and target_42.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_42.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_42.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand() instanceof SubExpr
}

predicate func_44(Parameter vs_0, ArrayExpr target_44) {
		target_44.getArrayBase().(PointerFieldAccess).getTarget().getName()="window"
		and target_44.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_44.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="strstart"
		and target_44.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_44.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_45(Parameter vs_0, ExprStmt target_45) {
		target_45.getExpr().(FunctionCall).getTarget().hasName("_tr_flush_block")
		and target_45.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_0
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="block_start"
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="window"
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="block_start"
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_45.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_45.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="strstart"
		and target_45.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_45.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="block_start"
		and target_45.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_45.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_46(Parameter vs_0, Variable vbflush_1944, IfStmt target_46) {
		target_46.getCondition().(VariableAccess).getTarget()=vbflush_1944
		and target_46.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_tr_flush_block")
		and target_46.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_0
		and target_46.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_46.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="strstart"
		and target_46.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="block_start"
		and target_46.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_47(Parameter vs_0, ExprStmt target_47) {
		target_47.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lookahead"
		and target_47.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_47.getExpr().(AssignSubExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="prev_length"
		and target_47.getExpr().(AssignSubExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_47.getExpr().(AssignSubExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_48(Parameter vs_0, ExprStmt target_48) {
		target_48.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="match_available"
		and target_48.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_48.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vs_0, Variable vbflush_1944, Variable vdist_2005, PointerFieldAccess target_0, PointerFieldAccess target_1, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, PointerFieldAccess target_9, PointerFieldAccess target_10, PointerFieldAccess target_11, PointerFieldAccess target_12, PointerFieldAccess target_13, Literal target_14, Literal target_15, Literal target_16, VariableAccess target_24, VariableAccess target_25, VariableAccess target_26, VariableAccess target_28, VariableAccess target_30, VariableAccess target_31, AssignExpr target_32, SubExpr target_33, AssignExpr target_34, SubExpr target_35, AssignExpr target_36, PointerFieldAccess target_37, SubExpr target_38, SubExpr target_39, ArrayExpr target_40, ExprStmt target_41, ExprStmt target_42, ArrayExpr target_44, ExprStmt target_45, IfStmt target_46, ExprStmt target_47, ExprStmt target_48
where
func_0(vs_0, target_0)
and func_1(vs_0, target_1)
and func_2(vs_0, target_2)
and func_3(vs_0, target_3)
and func_4(vs_0, target_4)
and func_5(vs_0, target_5)
and func_6(vs_0, target_6)
and func_7(vs_0, target_7)
and func_8(vs_0, target_8)
and func_9(vs_0, target_9)
and func_10(vs_0, target_10)
and func_11(vs_0, target_11)
and func_12(vs_0, target_12)
and func_13(vs_0, target_13)
and func_14(func, target_14)
and func_15(func, target_15)
and func_16(func, target_16)
and not func_17(vs_0, vdist_2005, target_39)
and not func_18(vs_0, vdist_2005, target_40)
and not func_19(vs_0, target_41, target_42)
and not func_20(vs_0)
and not func_21(vs_0, target_44)
and not func_22(vs_0)
and not func_23(vs_0, vbflush_1944, target_45, target_46)
and func_24(vs_0, target_24)
and func_25(vdist_2005, target_25)
and func_26(vs_0, target_26)
and func_28(vs_0, target_28)
and func_30(vs_0, target_30)
and func_31(vs_0, target_31)
and func_32(vs_0, vdist_2005, target_32)
and func_33(vs_0, target_47, target_33)
and func_34(vs_0, target_34)
and func_35(vs_0, target_45, target_35)
and func_36(vs_0, target_36)
and func_37(vs_0, target_37)
and func_38(vs_0, target_48, target_38)
and func_39(vs_0, target_39)
and func_40(vs_0, vdist_2005, target_40)
and func_41(vs_0, vbflush_1944, target_41)
and func_42(vs_0, vbflush_1944, target_42)
and func_44(vs_0, target_44)
and func_45(vs_0, target_45)
and func_46(vs_0, vbflush_1944, target_46)
and func_47(vs_0, target_47)
and func_48(vs_0, target_48)
and vs_0.getType().hasName("deflate_state *")
and vbflush_1944.getType().hasName("int")
and vdist_2005.getType().hasName("ush")
and vs_0.getParentScope+() = func
and vbflush_1944.getParentScope+() = func
and vdist_2005.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
