/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_rle
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflate-rle
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate.c-deflate_rle CVE-2018-25032
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
		target_9.getTarget().getName()="last_lit"
		and target_9.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_10(Function func, Literal target_10) {
		target_10.getValue()="1"
		and not target_10.getValue()="8"
		and target_10.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Function func, Literal target_11) {
		target_11.getValue()="1"
		and not target_11.getValue()="0"
		and target_11.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Parameter vs_0, Variable vdist_2115, SubExpr target_26) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_12.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getRValue().(VariableAccess).getTarget()=vdist_2115
		and target_26.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_13(Parameter vs_0, Variable vdist_2115, ExprStmt target_27, ExprStmt target_28, ArrayExpr target_29) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_13.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_13.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_13.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_13.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_2115
		and target_13.getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_27.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_28.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_29.getArrayOffset().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_13.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_14(Parameter vs_0, ArrayExpr target_30, ExprStmt target_27) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_14.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_14.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_14.getRValue() instanceof Literal
		and target_30.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_15(Parameter vs_0, ExprStmt target_32) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_15.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_16(Variable vbflush_2074, Parameter vs_0, ExprStmt target_28, IfStmt target_33) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_2074
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_33.getCondition().(VariableAccess).getLocation()))
}

predicate func_17(Parameter vs_0, VariableAccess target_17) {
		target_17.getTarget()=vs_0
}

predicate func_18(Variable vdist_2115, VariableAccess target_18) {
		target_18.getTarget()=vdist_2115
		and target_18.getParent().(AssignExpr).getRValue() = target_18
		and target_18.getParent().(AssignExpr).getLValue() instanceof ArrayExpr
}

predicate func_19(Parameter vs_0, VariableAccess target_19) {
		target_19.getTarget()=vs_0
}

predicate func_21(Parameter vs_0, VariableAccess target_21) {
		target_21.getTarget()=vs_0
}

predicate func_22(Parameter vs_0, Variable vdist_2115, AssignExpr target_22) {
		target_22.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_22.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_22.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_22.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_22.getRValue().(VariableAccess).getTarget()=vdist_2115
}

predicate func_23(Parameter vs_0, ExprStmt target_34, SubExpr target_23) {
		target_23.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_23.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_23.getRightOperand() instanceof Literal
		and target_23.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_34.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_24(Parameter vs_0, AssignExpr target_24) {
		target_24.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_24.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_24.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_24.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_24.getRValue() instanceof Literal
}

predicate func_25(Parameter vs_0, ExprStmt target_35, SubExpr target_25) {
		target_25.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_25.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_25.getRightOperand() instanceof Literal
		and target_25.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_35.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_26(Parameter vs_0, SubExpr target_26) {
		target_26.getLeftOperand().(PointerFieldAccess).getTarget().getName()="match_length"
		and target_26.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_26.getRightOperand().(Literal).getValue()="3"
}

predicate func_27(Variable vbflush_2074, Parameter vs_0, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_2074
		and target_27.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_27.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_27.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand() instanceof SubExpr
}

predicate func_28(Variable vbflush_2074, Parameter vs_0, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_2074
		and target_28.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_28.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_28.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand() instanceof SubExpr
}

predicate func_29(Parameter vs_0, Variable vdist_2115, ArrayExpr target_29) {
		target_29.getArrayBase().(PointerFieldAccess).getTarget().getName()="dyn_dtree"
		and target_29.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_29.getArrayOffset().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdist_2115
		and target_29.getArrayOffset().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_29.getArrayOffset().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vdist_2115
		and target_29.getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="256"
		and target_29.getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_2115
		and target_29.getArrayOffset().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
}

predicate func_30(Parameter vs_0, ArrayExpr target_30) {
		target_30.getArrayBase().(PointerFieldAccess).getTarget().getName()="dyn_ltree"
		and target_30.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_32(Parameter vs_0, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="l_buf"
		and target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_33(Variable vbflush_2074, Parameter vs_0, IfStmt target_33) {
		target_33.getCondition().(VariableAccess).getTarget()=vbflush_2074
		and target_33.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_tr_flush_block")
		and target_33.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_0
		and target_33.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_33.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="strstart"
		and target_33.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="block_start"
		and target_33.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_34(Parameter vs_0, ExprStmt target_34) {
		target_34.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lookahead"
		and target_34.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_34.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getTarget().getName()="match_length"
		and target_34.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_35(Parameter vs_0, ExprStmt target_35) {
		target_35.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lookahead"
		and target_35.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

from Function func, Variable vbflush_2074, Parameter vs_0, Variable vdist_2115, PointerFieldAccess target_0, PointerFieldAccess target_1, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, PointerFieldAccess target_9, Literal target_10, Literal target_11, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, VariableAccess target_21, AssignExpr target_22, SubExpr target_23, AssignExpr target_24, SubExpr target_25, SubExpr target_26, ExprStmt target_27, ExprStmt target_28, ArrayExpr target_29, ArrayExpr target_30, ExprStmt target_32, IfStmt target_33, ExprStmt target_34, ExprStmt target_35
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
and func_10(func, target_10)
and func_11(func, target_11)
and not func_12(vs_0, vdist_2115, target_26)
and not func_13(vs_0, vdist_2115, target_27, target_28, target_29)
and not func_14(vs_0, target_30, target_27)
and not func_15(vs_0, target_32)
and not func_16(vbflush_2074, vs_0, target_28, target_33)
and func_17(vs_0, target_17)
and func_18(vdist_2115, target_18)
and func_19(vs_0, target_19)
and func_21(vs_0, target_21)
and func_22(vs_0, vdist_2115, target_22)
and func_23(vs_0, target_34, target_23)
and func_24(vs_0, target_24)
and func_25(vs_0, target_35, target_25)
and func_26(vs_0, target_26)
and func_27(vbflush_2074, vs_0, target_27)
and func_28(vbflush_2074, vs_0, target_28)
and func_29(vs_0, vdist_2115, target_29)
and func_30(vs_0, target_30)
and func_32(vs_0, target_32)
and func_33(vbflush_2074, vs_0, target_33)
and func_34(vs_0, target_34)
and func_35(vs_0, target_35)
and vbflush_2074.getType().hasName("int")
and vs_0.getType().hasName("deflate_state *")
and vdist_2115.getType().hasName("ush")
and vbflush_2074.getParentScope+() = func
and vs_0.getParentScope+() = func
and vdist_2115.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
