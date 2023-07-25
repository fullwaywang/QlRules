/**
 * @name varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-http_splitheader
 * @id cpp/varnish/1cb778f6f69737109e8c070a74b8e95b78f46d13/http-splitheader
 * @description varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-bin/varnishtest/vtc_http.c-http_splitheader CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="((((p)[0] == 0x0d && (p)[1] == 0x0a) || (p)[0] == 0x0a)) == 0"
		and not target_0.getValue()="(vct_iscrlf(p, hp->rx_e)) == 0"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="((((p)[0] == 0x0d && (p)[1] == 0x0a) || (p)[0] == 0x0a)) == 0"
		and not target_1.getValue()="(vct_iscrlf(p, hp->rx_e)) == 0"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vhp_406, Variable vp_408, ExprStmt target_40, ExprStmt target_41) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("vct_iscrlf")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_40.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_41.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vhp_406, Variable vp_408) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("vct_iscrlf")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406)
}

predicate func_4(Parameter vhp_406, Variable vp_408, ExprStmt target_44) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("vct_iscrlf")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_4.getArgument(0).(VariableAccess).getLocation().isBefore(target_44.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vhp_406, Variable vp_408, ExprStmt target_45) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vp_408
		and target_5.getRValue().(FunctionCall).getTarget().hasName("vct_skipcrlf")
		and target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_5.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_5.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_45.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_5.getLValue().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vhp_406, Variable vp_408) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("vct_iscrlf")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_6.getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_6.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406)
}

predicate func_7(Parameter vhp_406, Variable vp_408, ExprStmt target_47, ExprStmt target_48) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vp_408
		and target_7.getRValue().(FunctionCall).getTarget().hasName("vct_skipcrlf")
		and target_7.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_7.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_7.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_47.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getLValue().(VariableAccess).getLocation())
		and target_7.getLValue().(VariableAccess).getLocation().isBefore(target_48.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vhp_406, Variable vp_408, ExprStmt target_49) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("vct_iscrlf")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_8.getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_8.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_49.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_9(Parameter vhp_406, Variable vp_408, LogicalOrExpr target_29) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("vct_iscrlf")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_9.getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_9.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_10(Parameter vhp_406, Variable vp_408, ExprStmt target_50, ExprStmt target_45) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=vp_408
		and target_10.getRValue().(FunctionCall).getTarget().hasName("vct_skipcrlf")
		and target_10.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_10.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_10.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_50.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_10.getLValue().(VariableAccess).getLocation())
		and target_10.getLValue().(VariableAccess).getLocation().isBefore(target_45.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_11(Parameter vhp_406, Variable vp_408, ExprStmt target_51) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(VariableAccess).getTarget()=vp_408
		and target_11.getRValue().(FunctionCall).getTarget().hasName("vct_skipcrlf")
		and target_11.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_408
		and target_11.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_11.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_11.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_51.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_12(Variable vp_408, EqualityOperation target_12) {
		target_12.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_408
		and target_12.getAnOperand().(CharLiteral).getValue()="0"
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand() instanceof LogicalOrExpr
}

predicate func_13(Variable vp_408, VariableAccess target_13) {
		target_13.getTarget()=vp_408
}

predicate func_14(Variable vp_408, VariableAccess target_14) {
		target_14.getTarget()=vp_408
}

predicate func_15(Variable vp_408, VariableAccess target_15) {
		target_15.getTarget()=vp_408
}

predicate func_16(Variable vp_408, VariableAccess target_16) {
		target_16.getTarget()=vp_408
}

predicate func_17(Variable vp_408, VariableAccess target_17) {
		target_17.getTarget()=vp_408
		and target_17.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_18(Variable vp_408, VariableAccess target_18) {
		target_18.getTarget()=vp_408
		and target_18.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_19(Variable vp_408, VariableAccess target_19) {
		target_19.getTarget()=vp_408
		and target_19.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_20(Variable vp_408, VariableAccess target_20) {
		target_20.getTarget()=vp_408
		and target_20.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_21(Variable vp_408, VariableAccess target_21) {
		target_21.getTarget()=vp_408
		and target_21.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_22(Variable vp_408, VariableAccess target_22) {
		target_22.getTarget()=vp_408
		and target_22.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_23(Variable vp_408, VariableAccess target_23) {
		target_23.getTarget()=vp_408
		and target_23.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_24(Variable vp_408, VariableAccess target_24) {
		target_24.getTarget()=vp_408
		and target_24.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_25(Variable vp_408, VariableAccess target_25) {
		target_25.getTarget()=vp_408
		and target_25.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_26(Variable vp_408, VariableAccess target_26) {
		target_26.getTarget()=vp_408
		and target_26.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_27(Variable vp_408, ExprStmt target_41, ExprStmt target_44, LogicalOrExpr target_27) {
		target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_41.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_44.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_28(Variable vp_408, ExprStmt target_53, ExprStmt target_48, LogicalOrExpr target_28) {
		target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_28.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_53.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_28.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_48.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_29(Variable vp_408, BlockStmt target_54, ExprStmt target_49, ExprStmt target_45, LogicalOrExpr target_29) {
		target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_29.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_29.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_29.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_29.getParent().(IfStmt).getThen()=target_54
		and target_49.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_45.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_30(Variable vp_408, ExprStmt target_45, ExprStmt target_55, AssignPointerAddExpr target_30) {
		target_30.getLValue().(VariableAccess).getTarget()=vp_408
		and target_30.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_30.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_30.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_30.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_30.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_30.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_30.getRValue().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_30.getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_45.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_30.getLValue().(VariableAccess).getLocation())
		and target_30.getLValue().(VariableAccess).getLocation().isBefore(target_55.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

/*predicate func_31(Variable vp_408, EqualityOperation target_31) {
		target_31.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_31.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_31.getAnOperand().(Literal).getValue()="13"
		and target_31.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_31.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_31.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
}

*/
/*predicate func_32(Variable vp_408, ExprStmt target_55, EqualityOperation target_32) {
		target_32.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_32.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_32.getAnOperand().(Literal).getValue()="10"
		and target_32.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_32.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_32.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_32.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_55.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

*/
predicate func_33(Variable vp_408, ExprStmt target_56, ExprStmt target_57, LogicalOrExpr target_33) {
		target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_33.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_33.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_33.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_56.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_57.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_34(Variable vp_408, ExprStmt target_47, EqualityOperation target_58, AssignPointerAddExpr target_34) {
		target_34.getLValue().(VariableAccess).getTarget()=vp_408
		and target_34.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_34.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_34.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_34.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_34.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_34.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_34.getRValue().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_34.getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_47.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_34.getLValue().(VariableAccess).getLocation())
		and target_34.getLValue().(VariableAccess).getLocation().isBefore(target_58.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_35(Variable vp_408, BreakStmt target_59, EqualityOperation target_58, ExprStmt target_60, LogicalOrExpr target_35) {
		target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_35.getParent().(IfStmt).getThen()=target_59
		and target_58.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_35.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_60.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_36(Variable vp_408, LogicalAndExpr target_36) {
		target_36.getAnOperand() instanceof EqualityOperation
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_36.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
}

/*predicate func_37(Variable vp_408, ExprStmt target_61, LogicalOrExpr target_37) {
		target_37.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_37.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_37.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_37.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_37.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_37.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_37.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_37.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_37.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_37.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_61.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

*/
predicate func_38(Variable vp_408, ExprStmt target_50, AssignPointerAddExpr target_38) {
		target_38.getLValue().(VariableAccess).getTarget()=vp_408
		and target_38.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_38.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_38.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_38.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_38.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_38.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_38.getRValue().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_38.getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_50.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_38.getLValue().(VariableAccess).getLocation())
}

predicate func_39(Variable vp_408, NotExpr target_64, AssignPointerAddExpr target_39) {
		target_39.getLValue().(VariableAccess).getTarget()=vp_408
		and target_39.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_39.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_39.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_39.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_408
		and target_39.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_39.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_39.getRValue().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_39.getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_39.getLValue().(VariableAccess).getLocation().isBefore(target_64.getOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_40(Parameter vhp_406, ExprStmt target_40) {
		target_40.getExpr().(FunctionCall).getTarget().hasName("vtc_log")
		and target_40.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vl"
		and target_40.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_40.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_40.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="No headers"
}

predicate func_41(Variable vp_408, ExprStmt target_41) {
		target_41.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
}

predicate func_44(Variable vp_408, ExprStmt target_44) {
		target_44.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
		and target_44.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_45(Variable vp_408, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_408
}

predicate func_47(Variable vp_408, ExprStmt target_47) {
		target_47.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_408
}

predicate func_48(Variable vp_408, ExprStmt target_48) {
		target_48.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_408
}

predicate func_49(Variable vp_408, ExprStmt target_49) {
		target_49.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
}

predicate func_50(Variable vp_408, ExprStmt target_50) {
		target_50.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_408
}

predicate func_51(Parameter vhp_406, ExprStmt target_51) {
		target_51.getExpr().(FunctionCall).getTarget().hasName("vtc_dump")
		and target_51.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vl"
		and target_51.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_406
		and target_51.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_51.getExpr().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
}

predicate func_53(Variable vp_408, ExprStmt target_53) {
		target_53.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
}

predicate func_54(Variable vp_408, BlockStmt target_54) {
		target_54.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_54.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_408
		and target_54.getStmt(2).(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_54.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_55(Variable vp_408, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
		and target_55.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_56(Variable vp_408, ExprStmt target_56) {
		target_56.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_408
}

predicate func_57(Variable vp_408, ExprStmt target_57) {
		target_57.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
}

predicate func_58(Variable vp_408, EqualityOperation target_58) {
		target_58.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_408
		and target_58.getAnOperand().(CharLiteral).getValue()="0"
}

predicate func_59(BreakStmt target_59) {
		target_59.toString() = "break;"
}

predicate func_60(Variable vp_408, ExprStmt target_60) {
		target_60.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
}

predicate func_61(Variable vp_408, ExprStmt target_61) {
		target_61.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_408
}

predicate func_64(Variable vp_408, NotExpr target_64) {
		target_64.getOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_408
		and target_64.getOperand().(EqualityOperation).getAnOperand() instanceof Literal
}

from Function func, Parameter vhp_406, Variable vp_408, StringLiteral target_0, StringLiteral target_1, EqualityOperation target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, VariableAccess target_16, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, VariableAccess target_22, VariableAccess target_23, VariableAccess target_24, VariableAccess target_25, VariableAccess target_26, LogicalOrExpr target_27, LogicalOrExpr target_28, LogicalOrExpr target_29, AssignPointerAddExpr target_30, LogicalOrExpr target_33, AssignPointerAddExpr target_34, LogicalOrExpr target_35, LogicalAndExpr target_36, AssignPointerAddExpr target_38, AssignPointerAddExpr target_39, ExprStmt target_40, ExprStmt target_41, ExprStmt target_44, ExprStmt target_45, ExprStmt target_47, ExprStmt target_48, ExprStmt target_49, ExprStmt target_50, ExprStmt target_51, ExprStmt target_53, BlockStmt target_54, ExprStmt target_55, ExprStmt target_56, ExprStmt target_57, EqualityOperation target_58, BreakStmt target_59, ExprStmt target_60, ExprStmt target_61, NotExpr target_64
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vhp_406, vp_408, target_40, target_41)
and not func_3(vhp_406, vp_408)
and not func_4(vhp_406, vp_408, target_44)
and not func_5(vhp_406, vp_408, target_45)
and not func_6(vhp_406, vp_408)
and not func_7(vhp_406, vp_408, target_47, target_48)
and not func_8(vhp_406, vp_408, target_49)
and not func_9(vhp_406, vp_408, target_29)
and not func_10(vhp_406, vp_408, target_50, target_45)
and not func_11(vhp_406, vp_408, target_51)
and func_12(vp_408, target_12)
and func_13(vp_408, target_13)
and func_14(vp_408, target_14)
and func_15(vp_408, target_15)
and func_16(vp_408, target_16)
and func_17(vp_408, target_17)
and func_18(vp_408, target_18)
and func_19(vp_408, target_19)
and func_20(vp_408, target_20)
and func_21(vp_408, target_21)
and func_22(vp_408, target_22)
and func_23(vp_408, target_23)
and func_24(vp_408, target_24)
and func_25(vp_408, target_25)
and func_26(vp_408, target_26)
and func_27(vp_408, target_41, target_44, target_27)
and func_28(vp_408, target_53, target_48, target_28)
and func_29(vp_408, target_54, target_49, target_45, target_29)
and func_30(vp_408, target_45, target_55, target_30)
and func_33(vp_408, target_56, target_57, target_33)
and func_34(vp_408, target_47, target_58, target_34)
and func_35(vp_408, target_59, target_58, target_60, target_35)
and func_36(vp_408, target_36)
and func_38(vp_408, target_50, target_38)
and func_39(vp_408, target_64, target_39)
and func_40(vhp_406, target_40)
and func_41(vp_408, target_41)
and func_44(vp_408, target_44)
and func_45(vp_408, target_45)
and func_47(vp_408, target_47)
and func_48(vp_408, target_48)
and func_49(vp_408, target_49)
and func_50(vp_408, target_50)
and func_51(vhp_406, target_51)
and func_53(vp_408, target_53)
and func_54(vp_408, target_54)
and func_55(vp_408, target_55)
and func_56(vp_408, target_56)
and func_57(vp_408, target_57)
and func_58(vp_408, target_58)
and func_59(target_59)
and func_60(vp_408, target_60)
and func_61(vp_408, target_61)
and func_64(vp_408, target_64)
and vhp_406.getType().hasName("http *")
and vp_408.getType().hasName("char *")
and vhp_406.getParentScope+() = func
and vp_408.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
