/**
 * @name varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-http1_dissect_hdrs
 * @id cpp/varnish/1cb778f6f69737109e8c070a74b8e95b78f46d13/http1-dissect-hdrs
 * @description varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-bin/varnishd/http1/cache_http1_proto.c-http1_dissect_hdrs CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vr_113, VariableAccess target_0) {
		target_0.getTarget()=vr_113
		and target_0.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_1(Variable vr_113, RelationalOperation target_21, VariableAccess target_1) {
		target_1.getTarget()=vr_113
		and target_1.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_1.getLocation().isBefore(target_21.getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_2(Parameter vhtc_110, RelationalOperation target_22, RelationalOperation target_23) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("vct_iscrlf")
		and target_2.getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_22.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vhtc_110, Variable vr_113, RelationalOperation target_23, NotExpr target_24, ExprStmt target_25) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("vct_iscrlf")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vr_113
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_23.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_25.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vhtc_110, Variable vr_113, NotExpr target_24) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vr_113
		and target_4.getRValue().(FunctionCall).getTarget().hasName("vct_skipcrlf")
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_113
		and target_4.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_4.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_24.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vhtc_110, Variable vr_113, RelationalOperation target_21, LogicalAndExpr target_26, PointerDereferenceExpr target_28) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("vct_iscrlf")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vr_113
		and target_5.getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_21.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getArgument(0).(VariableAccess).getLocation().isBefore(target_28.getOperand().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vhtc_110, RelationalOperation target_21) {
	exists(RelationalOperation target_6 |
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_6.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_6.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vp_110, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_7.getArrayOffset().(Literal).getValue()="0"
}

predicate func_8(Parameter vp_110, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_8.getArrayOffset().(Literal).getValue()="1"
}

predicate func_9(Parameter vp_110, ArrayExpr target_9) {
		target_9.getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_9.getArrayOffset().(Literal).getValue()="0"
}

predicate func_10(Variable vq_113, FunctionCall target_10) {
		target_10.getTarget().hasName("vct_is")
		and target_10.getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vq_113
		and target_10.getArgument(1).(BitwiseOrExpr).getValue()="3"
}

predicate func_11(Variable vr_113, VariableAccess target_11) {
		target_11.getTarget()=vr_113
}

predicate func_12(Variable vr_113, VariableAccess target_12) {
		target_12.getTarget()=vr_113
		and target_12.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_13(Variable vr_113, VariableAccess target_13) {
		target_13.getTarget()=vr_113
		and target_13.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_14(Variable vr_113, VariableAccess target_14) {
		target_14.getTarget()=vr_113
		and target_14.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_15(BreakStmt target_29, Function func, LogicalOrExpr target_15) {
		target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_15.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_15.getAnOperand().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_15.getParent().(IfStmt).getThen()=target_29
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Variable vr_113, BlockStmt target_30, ExprStmt target_25, PointerDereferenceExpr target_28, LogicalOrExpr target_16) {
		target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_16.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_30
		and target_25.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_28.getOperand().(VariableAccess).getLocation())
}

predicate func_17(Variable vr_113, AssignPointerAddExpr target_17) {
		target_17.getLValue().(VariableAccess).getTarget()=vr_113
		and target_17.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_17.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_17.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_17.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_17.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_17.getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_17.getRValue().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_17.getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

/*predicate func_18(Variable vr_113, EqualityOperation target_18) {
		target_18.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_18.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_18.getAnOperand().(Literal).getValue()="13"
		and target_18.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_18.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_18.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
}

*/
/*predicate func_19(Variable vr_113, RelationalOperation target_21, EqualityOperation target_19) {
		target_19.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_19.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_19.getAnOperand().(Literal).getValue()="10"
		and target_19.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_21.getGreaterOperand().(VariableAccess).getLocation())
}

*/
predicate func_20(Variable vr_113, BreakStmt target_31, RelationalOperation target_21, PointerDereferenceExpr target_32, LogicalOrExpr target_20) {
		target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_20.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_113
		and target_20.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_20.getParent().(IfStmt).getThen()=target_31
		and target_21.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_20.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_32.getOperand().(VariableAccess).getLocation())
}

predicate func_21(Parameter vhtc_110, Variable vr_113, RelationalOperation target_21) {
		 (target_21 instanceof GEExpr or target_21 instanceof LEExpr)
		and target_21.getGreaterOperand().(VariableAccess).getTarget()=vr_113
		and target_21.getLesserOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_21.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_22(Parameter vp_110, Parameter vhtc_110, RelationalOperation target_22) {
		 (target_22 instanceof GTExpr or target_22 instanceof LTExpr)
		and target_22.getLesserOperand().(VariableAccess).getTarget()=vp_110
		and target_22.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_22.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_23(Parameter vhtc_110, Variable vr_113, RelationalOperation target_23) {
		 (target_23 instanceof GTExpr or target_23 instanceof LTExpr)
		and target_23.getLesserOperand().(VariableAccess).getTarget()=vr_113
		and target_23.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_23.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_24(Parameter vhtc_110, Variable vr_113, NotExpr target_24) {
		target_24.getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_113
		and target_24.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_24.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_25(Variable vr_113, ExprStmt target_25) {
		target_25.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vr_113
}

predicate func_26(Parameter vp_110, Parameter vhtc_110, LogicalAndExpr target_26) {
		target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_110
		and target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_26.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="13"
		and target_26.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_26.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_26.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
}

predicate func_28(Variable vr_113, PointerDereferenceExpr target_28) {
		target_28.getOperand().(VariableAccess).getTarget()=vr_113
}

predicate func_29(BreakStmt target_29) {
		target_29.toString() = "break;"
}

predicate func_30(Variable vr_113, BlockStmt target_30) {
		target_30.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_30.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_30.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Header has ctrl char 0x%02x"
		and target_30.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vr_113
		and target_30.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="400"
}

predicate func_31(BreakStmt target_31) {
		target_31.toString() = "break;"
}

predicate func_32(Variable vr_113, PointerDereferenceExpr target_32) {
		target_32.getOperand().(VariableAccess).getTarget()=vr_113
}

from Function func, Parameter vp_110, Parameter vhtc_110, Variable vq_113, Variable vr_113, VariableAccess target_0, VariableAccess target_1, ArrayExpr target_7, ArrayExpr target_8, ArrayExpr target_9, FunctionCall target_10, VariableAccess target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, LogicalOrExpr target_15, LogicalOrExpr target_16, AssignPointerAddExpr target_17, LogicalOrExpr target_20, RelationalOperation target_21, RelationalOperation target_22, RelationalOperation target_23, NotExpr target_24, ExprStmt target_25, LogicalAndExpr target_26, PointerDereferenceExpr target_28, BreakStmt target_29, BlockStmt target_30, BreakStmt target_31, PointerDereferenceExpr target_32
where
func_0(vr_113, target_0)
and func_1(vr_113, target_21, target_1)
and not func_2(vhtc_110, target_22, target_23)
and not func_3(vhtc_110, vr_113, target_23, target_24, target_25)
and not func_4(vhtc_110, vr_113, target_24)
and not func_5(vhtc_110, vr_113, target_21, target_26, target_28)
and not func_6(vhtc_110, target_21)
and func_7(vp_110, target_7)
and func_8(vp_110, target_8)
and func_9(vp_110, target_9)
and func_10(vq_113, target_10)
and func_11(vr_113, target_11)
and func_12(vr_113, target_12)
and func_13(vr_113, target_13)
and func_14(vr_113, target_14)
and func_15(target_29, func, target_15)
and func_16(vr_113, target_30, target_25, target_28, target_16)
and func_17(vr_113, target_17)
and func_20(vr_113, target_31, target_21, target_32, target_20)
and func_21(vhtc_110, vr_113, target_21)
and func_22(vp_110, vhtc_110, target_22)
and func_23(vhtc_110, vr_113, target_23)
and func_24(vhtc_110, vr_113, target_24)
and func_25(vr_113, target_25)
and func_26(vp_110, vhtc_110, target_26)
and func_28(vr_113, target_28)
and func_29(target_29)
and func_30(vr_113, target_30)
and func_31(target_31)
and func_32(vr_113, target_32)
and vp_110.getType().hasName("char *")
and vhtc_110.getType().hasName("http_conn *")
and vq_113.getType().hasName("char *")
and vr_113.getType().hasName("char *")
and vp_110.getParentScope+() = func
and vhtc_110.getParentScope+() = func
and vq_113.getParentScope+() = func
and vr_113.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
