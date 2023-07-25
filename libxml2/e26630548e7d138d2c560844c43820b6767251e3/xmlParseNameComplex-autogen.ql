/**
 * @name libxml2-e26630548e7d138d2c560844c43820b6767251e3-xmlParseNameComplex
 * @id cpp/libxml2/e26630548e7d138d2c560844c43820b6767251e3/xmlParseNameComplex
 * @description libxml2-e26630548e7d138d2c560844c43820b6767251e3-parser.c-xmlParseNameComplex CVE-2017-9049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, FunctionCall target_0) {
		target_0.getTarget().hasName("xmlCurrentChar__internal_alias")
		and not target_0.getTarget().hasName("xmlCurrentChar")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
}

predicate func_1(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, FunctionCall target_1) {
		target_1.getTarget().hasName("xmlCurrentChar__internal_alias")
		and not target_1.getTarget().hasName("xmlCurrentChar")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
}

predicate func_2(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, FunctionCall target_2) {
		target_2.getTarget().hasName("xmlCurrentChar__internal_alias")
		and not target_2.getTarget().hasName("xmlCurrentChar")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
}

predicate func_3(Variable vc_3319, Variable vxmlIsBaseCharGroup, FunctionCall target_3) {
		target_3.getTarget().hasName("xmlCharInRange__internal_alias")
		and not target_3.getTarget().hasName("xmlCharInRange")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vc_3319
		and target_3.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vxmlIsBaseCharGroup
}

predicate func_4(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, FunctionCall target_4) {
		target_4.getTarget().hasName("xmlCurrentChar__internal_alias")
		and not target_4.getTarget().hasName("xmlCurrentChar")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
}

predicate func_5(Variable vc_3319, Variable vxmlIsBaseCharGroup, FunctionCall target_5) {
		target_5.getTarget().hasName("xmlCharInRange__internal_alias")
		and not target_5.getTarget().hasName("xmlCharInRange")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vc_3319
		and target_5.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vxmlIsBaseCharGroup
}

predicate func_6(Variable vc_3319, Variable vxmlIsDigitGroup, FunctionCall target_6) {
		target_6.getTarget().hasName("xmlCharInRange__internal_alias")
		and not target_6.getTarget().hasName("xmlCharInRange")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vc_3319
		and target_6.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vxmlIsDigitGroup
}

predicate func_7(Variable vxmlIsCombiningGroup, Variable vc_3319, FunctionCall target_7) {
		target_7.getTarget().hasName("xmlCharInRange__internal_alias")
		and not target_7.getTarget().hasName("xmlCharInRange")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vc_3319
		and target_7.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vxmlIsCombiningGroup
}

predicate func_8(Variable vc_3319, Variable vxmlIsExtenderGroup, FunctionCall target_8) {
		target_8.getTarget().hasName("xmlCharInRange__internal_alias")
		and not target_8.getTarget().hasName("xmlCharInRange")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vc_3319
		and target_8.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vxmlIsExtenderGroup
}

predicate func_9(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, FunctionCall target_9) {
		target_9.getTarget().hasName("xmlCurrentChar__internal_alias")
		and not target_9.getTarget().hasName("xmlCurrentChar")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_9.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
}

predicate func_10(Parameter vctxt_3317, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="end"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
}

predicate func_11(Parameter vctxt_3317, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="cur"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
}

predicate func_12(Parameter vctxt_3317, Variable vlen_3318, FunctionCall target_12) {
		target_12.getTarget().hasName("xmlDictLookup__internal_alias")
		and not target_12.getTarget().hasName("xmlDictLookup")
		and target_12.getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_12.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_12.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_12.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_12.getArgument(1).(PointerArithmeticOperation).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_3318
		and target_12.getArgument(1).(PointerArithmeticOperation).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_12.getArgument(2).(VariableAccess).getTarget()=vlen_3318
}

predicate func_13(Parameter vctxt_3317, Variable vlen_3318, FunctionCall target_13) {
		target_13.getTarget().hasName("xmlDictLookup__internal_alias")
		and not target_13.getTarget().hasName("xmlDictLookup")
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_13.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_13.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_13.getArgument(1).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vlen_3318
		and target_13.getArgument(2).(VariableAccess).getTarget()=vlen_3318
}

predicate func_14(Parameter vctxt_3317, FunctionCall target_14) {
		target_14.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_14.getTarget().hasName("xmlFatalErr")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vctxt_3317
}

predicate func_15(Variable vc_3319, BlockStmt target_37, ExprStmt target_38, VariableAccess target_15) {
		target_15.getTarget()=vc_3319
		and target_15.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_15.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_37
		and target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getLocation())
}

predicate func_17(Parameter vctxt_3317, LogicalAndExpr target_39) {
	exists(PointerFieldAccess target_17 |
		target_17.getTarget().getName()="base"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_39.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_19(Parameter vctxt_3317, ExprStmt target_26, PointerDereferenceExpr target_19) {
		target_19.getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_19.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_19.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_19.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_19.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_26
}

predicate func_20(Parameter vctxt_3317, ExprStmt target_40, PointerDereferenceExpr target_20) {
		target_20.getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_20.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_20.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_20.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_20.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_40
}

predicate func_21(Parameter vctxt_3317, ExprStmt target_41, PointerDereferenceExpr target_21) {
		target_21.getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_21.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_21.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_41
}

predicate func_22(Parameter vctxt_3317, PointerFieldAccess target_22) {
		target_22.getTarget().getName()="cur"
		and target_22.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_22.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
}

predicate func_23(Parameter vctxt_3317, PointerFieldAccess target_23) {
		target_23.getTarget().getName()="input"
		and target_23.getQualifier().(VariableAccess).getTarget()=vctxt_3317
}

predicate func_24(EqualityOperation target_42, Function func, ReturnStmt target_24) {
		target_24.getExpr().(Literal).getValue()="0"
		and target_24.getParent().(IfStmt).getCondition()=target_42
		and target_24.getEnclosingFunction() = func
}

predicate func_25(Function func, EqualityOperation target_25) {
		target_25.getAnOperand() instanceof PointerDereferenceExpr
		and target_25.getAnOperand().(Literal).getValue()="37"
		and target_25.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_25.getEnclosingFunction() = func
}

predicate func_26(EqualityOperation target_25, Function func, ExprStmt target_26) {
		target_26.getExpr() instanceof FunctionCall
		and target_26.getParent().(IfStmt).getCondition()=target_25
		and target_26.getEnclosingFunction() = func
}

predicate func_27(Parameter vctxt_3317, IfStmt target_27) {
		target_27.getCondition().(EqualityOperation).getAnOperand() instanceof PointerDereferenceExpr
		and target_27.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="37"
		and target_27.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and target_27.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
}

predicate func_28(Parameter vctxt_3317, IfStmt target_28) {
		target_28.getCondition().(EqualityOperation).getAnOperand() instanceof PointerDereferenceExpr
		and target_28.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="37"
		and target_28.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and target_28.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
}

predicate func_29(Parameter vctxt_3317, ExprStmt target_38, IfStmt target_29) {
		target_29.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_29.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_29.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_29.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="37"
		and target_29.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and target_29.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
}

predicate func_30(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, Variable vcount_3320, IfStmt target_30) {
		target_30.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_3319
		and target_30.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_3320
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="progressive"
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="250"
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlGROW")
		and target_30.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_30.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_30.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_30.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_30.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen() instanceof ReturnStmt
		and target_30.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
		and target_30.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlCurrentChar__internal_alias")
		and target_30.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_30.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318
}

/*predicate func_31(Variable vcount_3320, ExprStmt target_45, AssignExpr target_31) {
		target_31.getLValue().(VariableAccess).getTarget()=vcount_3320
		and target_31.getRValue().(Literal).getValue()="0"
		and target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_31.getLValue().(VariableAccess).getLocation())
}

*/
/*predicate func_32(Parameter vctxt_3317, EqualityOperation target_46, IfStmt target_32) {
		target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="progressive"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_32.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="250"
		and target_32.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlGROW")
		and target_32.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_32.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

*/
/*predicate func_34(EqualityOperation target_46, Function func, EmptyStmt target_34) {
		target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
		and target_34.getEnclosingFunction() = func
}

*/
/*predicate func_35(Parameter vctxt_3317, EqualityOperation target_46, ExprStmt target_36, IfStmt target_35) {
		target_35.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_35.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_35.getCondition().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_35.getThen() instanceof ReturnStmt
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
		and target_35.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_36(Parameter vctxt_3317, Variable vl_3318, Variable vc_3319, ExprStmt target_36) {
		target_36.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlCurrentChar__internal_alias")
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3317
		and target_36.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3318
}

predicate func_37(BlockStmt target_37) {
		target_37.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and target_37.getStmt(1) instanceof IfStmt
		and target_37.getStmt(2) instanceof EmptyStmt
		and target_37.getStmt(3) instanceof IfStmt
		and target_37.getStmt(4) instanceof ExprStmt
}

predicate func_38(Variable vc_3319, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3319
		and target_38.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_39(Parameter vctxt_3317, LogicalAndExpr target_39) {
		target_39.getAnOperand() instanceof EqualityOperation
		and target_39.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_39.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_39.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_39.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_39.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_39.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_39.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
}

predicate func_40(ExprStmt target_40) {
		target_40.getExpr() instanceof FunctionCall
}

predicate func_41(ExprStmt target_41) {
		target_41.getExpr() instanceof FunctionCall
}

predicate func_42(Parameter vctxt_3317, EqualityOperation target_42) {
		target_42.getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_42.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3317
		and target_42.getAnOperand() instanceof EnumConstantAccess
}

predicate func_45(Variable vcount_3320, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_3320
		and target_45.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_46(Variable vc_3319, EqualityOperation target_46) {
		target_46.getAnOperand().(VariableAccess).getTarget()=vc_3319
		and target_46.getAnOperand() instanceof Literal
}

from Function func, Variable vxmlIsCombiningGroup, Parameter vctxt_3317, Variable vlen_3318, Variable vl_3318, Variable vc_3319, Variable vcount_3320, Variable vxmlIsBaseCharGroup, Variable vxmlIsDigitGroup, Variable vxmlIsExtenderGroup, FunctionCall target_0, FunctionCall target_1, FunctionCall target_2, FunctionCall target_3, FunctionCall target_4, FunctionCall target_5, FunctionCall target_6, FunctionCall target_7, FunctionCall target_8, FunctionCall target_9, PointerFieldAccess target_10, PointerFieldAccess target_11, FunctionCall target_12, FunctionCall target_13, FunctionCall target_14, VariableAccess target_15, PointerDereferenceExpr target_19, PointerDereferenceExpr target_20, PointerDereferenceExpr target_21, PointerFieldAccess target_22, PointerFieldAccess target_23, ReturnStmt target_24, EqualityOperation target_25, ExprStmt target_26, IfStmt target_27, IfStmt target_28, IfStmt target_29, IfStmt target_30, ExprStmt target_36, BlockStmt target_37, ExprStmt target_38, LogicalAndExpr target_39, ExprStmt target_40, ExprStmt target_41, EqualityOperation target_42, ExprStmt target_45, EqualityOperation target_46
where
func_0(vctxt_3317, vl_3318, vc_3319, target_0)
and func_1(vctxt_3317, vl_3318, vc_3319, target_1)
and func_2(vctxt_3317, vl_3318, vc_3319, target_2)
and func_3(vc_3319, vxmlIsBaseCharGroup, target_3)
and func_4(vctxt_3317, vl_3318, vc_3319, target_4)
and func_5(vc_3319, vxmlIsBaseCharGroup, target_5)
and func_6(vc_3319, vxmlIsDigitGroup, target_6)
and func_7(vxmlIsCombiningGroup, vc_3319, target_7)
and func_8(vc_3319, vxmlIsExtenderGroup, target_8)
and func_9(vctxt_3317, vl_3318, vc_3319, target_9)
and func_10(vctxt_3317, target_10)
and func_11(vctxt_3317, target_11)
and func_12(vctxt_3317, vlen_3318, target_12)
and func_13(vctxt_3317, vlen_3318, target_13)
and func_14(vctxt_3317, target_14)
and func_15(vc_3319, target_37, target_38, target_15)
and not func_17(vctxt_3317, target_39)
and func_19(vctxt_3317, target_26, target_19)
and func_20(vctxt_3317, target_40, target_20)
and func_21(vctxt_3317, target_41, target_21)
and func_22(vctxt_3317, target_22)
and func_23(vctxt_3317, target_23)
and func_24(target_42, func, target_24)
and func_25(func, target_25)
and func_26(target_25, func, target_26)
and func_27(vctxt_3317, target_27)
and func_28(vctxt_3317, target_28)
and func_29(vctxt_3317, target_38, target_29)
and func_30(vctxt_3317, vl_3318, vc_3319, vcount_3320, target_30)
and func_36(vctxt_3317, vl_3318, vc_3319, target_36)
and func_37(target_37)
and func_38(vc_3319, target_38)
and func_39(vctxt_3317, target_39)
and func_40(target_40)
and func_41(target_41)
and func_42(vctxt_3317, target_42)
and func_45(vcount_3320, target_45)
and func_46(vc_3319, target_46)
and vxmlIsCombiningGroup.getType().hasName("const xmlChRangeGroup")
and vctxt_3317.getType().hasName("xmlParserCtxtPtr")
and vlen_3318.getType().hasName("int")
and vl_3318.getType().hasName("int")
and vc_3319.getType().hasName("int")
and vcount_3320.getType().hasName("int")
and vxmlIsBaseCharGroup.getType().hasName("const xmlChRangeGroup")
and vxmlIsDigitGroup.getType().hasName("const xmlChRangeGroup")
and vxmlIsExtenderGroup.getType().hasName("const xmlChRangeGroup")
and not vxmlIsCombiningGroup.getParentScope+() = func
and vctxt_3317.getFunction() = func
and vlen_3318.(LocalVariable).getFunction() = func
and vl_3318.(LocalVariable).getFunction() = func
and vc_3319.(LocalVariable).getFunction() = func
and vcount_3320.(LocalVariable).getFunction() = func
and not vxmlIsBaseCharGroup.getParentScope+() = func
and not vxmlIsDigitGroup.getParentScope+() = func
and not vxmlIsExtenderGroup.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
