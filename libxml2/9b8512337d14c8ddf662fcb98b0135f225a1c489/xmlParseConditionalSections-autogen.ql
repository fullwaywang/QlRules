/**
 * @name libxml2-9b8512337d14c8ddf662fcb98b0135f225a1c489-xmlParseConditionalSections
 * @id cpp/libxml2/9b8512337d14c8ddf662fcb98b0135f225a1c489/xmlParseConditionalSections
 * @description libxml2-9b8512337d14c8ddf662fcb98b0135f225a1c489-parser.c-xmlParseConditionalSections CVE-2015-7941
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_6763, FunctionCall target_0) {
		target_0.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_0.getTarget().hasName("xmlParserHandlePEReference")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_1(Parameter vctxt_6763, FunctionCall target_1) {
		target_1.getTarget().hasName("xmlParserInputGrow__internal_alias")
		and not target_1.getTarget().hasName("xmlParserInputGrow")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_1.getArgument(1).(Literal).getValue()="250"
}

predicate func_2(Parameter vctxt_6763, FunctionCall target_2) {
		target_2.getTarget().hasName("xmlPopInput__internal_alias")
		and not target_2.getTarget().hasName("xmlPopInput")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_3(Parameter vctxt_6763, FunctionCall target_3) {
		target_3.getTarget().hasName("xmlSkipBlankChars__internal_alias")
		and not target_3.getTarget().hasName("xmlSkipBlankChars")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_4(Parameter vctxt_6763, FunctionCall target_4) {
		target_4.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_4.getTarget().hasName("xmlParserHandlePEReference")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_5(Parameter vctxt_6763, FunctionCall target_5) {
		target_5.getTarget().hasName("xmlParserInputGrow__internal_alias")
		and not target_5.getTarget().hasName("xmlParserInputGrow")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_5.getArgument(1).(Literal).getValue()="250"
}

predicate func_6(Parameter vctxt_6763, FunctionCall target_6) {
		target_6.getTarget().hasName("xmlPopInput__internal_alias")
		and not target_6.getTarget().hasName("xmlPopInput")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_7(Parameter vctxt_6763, FunctionCall target_7) {
		target_7.getTarget().hasName("xmlSkipBlankChars__internal_alias")
		and not target_7.getTarget().hasName("xmlSkipBlankChars")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_8(Parameter vctxt_6763, FunctionCall target_8) {
		target_8.getTarget().hasName("xmlNextChar__internal_alias")
		and not target_8.getTarget().hasName("xmlNextChar")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_9(Function func, FunctionCall target_9) {
		target_9.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_9.getTarget().hasName("__xmlGenericError")
		and target_9.getEnclosingFunction() = func
}

*/
predicate func_10(Parameter vctxt_6763, FunctionCall target_10) {
		target_10.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_10.getTarget().hasName("__xmlGenericErrorContext")
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="%s(%d): "
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="filename"
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="line"
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_10.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_11(Function func, FunctionCall target_11) {
		target_11.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_11.getTarget().hasName("__xmlGenericError")
		and target_11.getEnclosingFunction() = func
}

*/
predicate func_12(Function func, FunctionCall target_12) {
		target_12.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_12.getTarget().hasName("__xmlGenericErrorContext")
		and target_12.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_12.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="Entering INCLUDE Conditional Section\n"
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Parameter vctxt_6763, FunctionCall target_13) {
		target_13.getTarget().hasName("xmlNextChar__internal_alias")
		and not target_13.getTarget().hasName("xmlNextChar")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_14(Parameter vctxt_6763, FunctionCall target_14) {
		target_14.getTarget().hasName("xmlParsePEReference__internal_alias")
		and not target_14.getTarget().hasName("xmlParsePEReference")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_15(Parameter vctxt_6763, FunctionCall target_15) {
		target_15.getTarget().hasName("xmlParseMarkupDecl__internal_alias")
		and not target_15.getTarget().hasName("xmlParseMarkupDecl")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_16(Parameter vctxt_6763, FunctionCall target_16) {
		target_16.getTarget().hasName("xmlPopInput__internal_alias")
		and not target_16.getTarget().hasName("xmlPopInput")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_17(Function func, FunctionCall target_17) {
		target_17.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_17.getTarget().hasName("__xmlGenericError")
		and target_17.getEnclosingFunction() = func
}

*/
predicate func_18(Parameter vctxt_6763, FunctionCall target_18) {
		target_18.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_18.getTarget().hasName("__xmlGenericErrorContext")
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="%s(%d): "
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="filename"
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="line"
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_18.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_19(Function func, FunctionCall target_19) {
		target_19.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_19.getTarget().hasName("__xmlGenericError")
		and target_19.getEnclosingFunction() = func
}

*/
predicate func_20(Function func, FunctionCall target_20) {
		target_20.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_20.getTarget().hasName("__xmlGenericErrorContext")
		and target_20.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_20.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="Leaving INCLUDE Conditional Section\n"
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Parameter vctxt_6763, FunctionCall target_21) {
		target_21.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_21.getTarget().hasName("xmlParserHandlePEReference")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_22(Parameter vctxt_6763, FunctionCall target_22) {
		target_22.getTarget().hasName("xmlParserInputGrow__internal_alias")
		and not target_22.getTarget().hasName("xmlParserInputGrow")
		and target_22.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_22.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_22.getArgument(1).(Literal).getValue()="250"
}

predicate func_23(Parameter vctxt_6763, FunctionCall target_23) {
		target_23.getTarget().hasName("xmlPopInput__internal_alias")
		and not target_23.getTarget().hasName("xmlPopInput")
		and target_23.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_24(Parameter vctxt_6763, FunctionCall target_24) {
		target_24.getTarget().hasName("xmlSkipBlankChars__internal_alias")
		and not target_24.getTarget().hasName("xmlSkipBlankChars")
		and target_24.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_25(Parameter vctxt_6763, FunctionCall target_25) {
		target_25.getTarget().hasName("xmlNextChar__internal_alias")
		and not target_25.getTarget().hasName("xmlNextChar")
		and target_25.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_26(Function func, FunctionCall target_26) {
		target_26.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_26.getTarget().hasName("__xmlGenericError")
		and target_26.getEnclosingFunction() = func
}

*/
predicate func_27(Parameter vctxt_6763, FunctionCall target_27) {
		target_27.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_27.getTarget().hasName("__xmlGenericErrorContext")
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="%s(%d): "
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="filename"
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="line"
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_27.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_28(Function func, FunctionCall target_28) {
		target_28.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_28.getTarget().hasName("__xmlGenericError")
		and target_28.getEnclosingFunction() = func
}

*/
predicate func_29(Function func, FunctionCall target_29) {
		target_29.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_29.getTarget().hasName("__xmlGenericErrorContext")
		and target_29.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_29.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="Entering IGNORE Conditional Section\n"
		and target_29.getEnclosingFunction() = func
}

predicate func_30(Parameter vctxt_6763, FunctionCall target_30) {
		target_30.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_30.getTarget().hasName("xmlParserHandlePEReference")
		and target_30.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_31(Parameter vctxt_6763, FunctionCall target_31) {
		target_31.getTarget().hasName("xmlParserInputGrow__internal_alias")
		and not target_31.getTarget().hasName("xmlParserInputGrow")
		and target_31.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_31.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_31.getArgument(1).(Literal).getValue()="250"
}

predicate func_32(Parameter vctxt_6763, FunctionCall target_32) {
		target_32.getTarget().hasName("xmlPopInput__internal_alias")
		and not target_32.getTarget().hasName("xmlPopInput")
		and target_32.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_33(Parameter vctxt_6763, FunctionCall target_33) {
		target_33.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_33.getTarget().hasName("xmlParserHandlePEReference")
		and target_33.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_34(Parameter vctxt_6763, FunctionCall target_34) {
		target_34.getTarget().hasName("xmlParserInputGrow__internal_alias")
		and not target_34.getTarget().hasName("xmlParserInputGrow")
		and target_34.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_34.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_34.getArgument(1).(Literal).getValue()="250"
}

predicate func_35(Parameter vctxt_6763, FunctionCall target_35) {
		target_35.getTarget().hasName("xmlPopInput__internal_alias")
		and not target_35.getTarget().hasName("xmlPopInput")
		and target_35.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_36(Parameter vctxt_6763, FunctionCall target_36) {
		target_36.getTarget().hasName("xmlNextChar__internal_alias")
		and not target_36.getTarget().hasName("xmlNextChar")
		and target_36.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_37(Function func, FunctionCall target_37) {
		target_37.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_37.getTarget().hasName("__xmlGenericError")
		and target_37.getEnclosingFunction() = func
}

*/
predicate func_38(Parameter vctxt_6763, FunctionCall target_38) {
		target_38.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_38.getTarget().hasName("__xmlGenericErrorContext")
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="%s(%d): "
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="filename"
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="line"
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_38.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
}

/*predicate func_39(Function func, FunctionCall target_39) {
		target_39.getTarget().hasName("__xmlGenericError__internal_alias")
		and not target_39.getTarget().hasName("__xmlGenericError")
		and target_39.getEnclosingFunction() = func
}

*/
predicate func_40(Function func, FunctionCall target_40) {
		target_40.getTarget().hasName("__xmlGenericErrorContext__internal_alias")
		and not target_40.getTarget().hasName("__xmlGenericErrorContext")
		and target_40.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError__internal_alias")
		and target_40.getParent().(PointerDereferenceExpr).getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="Leaving IGNORE Conditional Section\n"
		and target_40.getEnclosingFunction() = func
}

predicate func_41(Parameter vctxt_6763, FunctionCall target_41) {
		target_41.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_41.getTarget().hasName("xmlParserHandlePEReference")
		and target_41.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_42(Parameter vctxt_6763, FunctionCall target_42) {
		target_42.getTarget().hasName("xmlParserInputGrow__internal_alias")
		and not target_42.getTarget().hasName("xmlParserInputGrow")
		and target_42.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_42.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_42.getArgument(1).(Literal).getValue()="250"
}

predicate func_43(Parameter vctxt_6763, FunctionCall target_43) {
		target_43.getTarget().hasName("xmlPopInput__internal_alias")
		and not target_43.getTarget().hasName("xmlPopInput")
		and target_43.getArgument(0).(VariableAccess).getTarget()=vctxt_6763
}

predicate func_44(Parameter vctxt_6763, EqualityOperation target_50, ExprStmt target_51, EqualityOperation target_52) {
	exists(ExprStmt target_44 |
		target_44.getExpr().(FunctionCall).getTarget().hasName("xmlStopParser")
		and target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6763
		and target_44.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_44
		and target_44.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_50
		and target_51.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_52.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_45(EqualityOperation target_50, Function func) {
	exists(ReturnStmt target_45 |
		target_45.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_45
		and target_45.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_50
		and target_45.getEnclosingFunction() = func)
}

predicate func_46(Parameter vctxt_6763, EqualityOperation target_53, ExprStmt target_54, EqualityOperation target_55) {
	exists(ExprStmt target_46 |
		target_46.getExpr().(FunctionCall).getTarget().hasName("xmlStopParser")
		and target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6763
		and target_46.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_46
		and target_46.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
		and target_54.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_46.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_55.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_47(EqualityOperation target_53, Function func) {
	exists(ReturnStmt target_47 |
		target_47.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_47
		and target_47.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_53
		and target_47.getEnclosingFunction() = func)
}

predicate func_48(Parameter vctxt_6763, LogicalAndExpr target_56, ExprStmt target_57, EqualityOperation target_58) {
	exists(ExprStmt target_48 |
		target_48.getExpr().(FunctionCall).getTarget().hasName("xmlStopParser")
		and target_48.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6763
		and target_48.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_48
		and target_48.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_56
		and target_57.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_48.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_48.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_58.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_49(LogicalAndExpr target_56, Function func) {
	exists(ReturnStmt target_49 |
		target_49.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_49
		and target_49.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_56
		and target_49.getEnclosingFunction() = func)
}

predicate func_50(Parameter vctxt_6763, EqualityOperation target_50) {
		target_50.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_50.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_50.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_50.getAnOperand().(CharLiteral).getValue()="91"
}

predicate func_51(Parameter vctxt_6763, ExprStmt target_51) {
		target_51.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_51.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6763
		and target_51.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_52(Parameter vctxt_6763, EqualityOperation target_52) {
		target_52.getAnOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_52.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_52.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_52.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_53(Parameter vctxt_6763, EqualityOperation target_53) {
		target_53.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_53.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_53.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_53.getAnOperand().(CharLiteral).getValue()="91"
}

predicate func_54(Parameter vctxt_6763, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_54.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6763
		and target_54.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_55(Parameter vctxt_6763, EqualityOperation target_55) {
		target_55.getAnOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_55.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_55.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_55.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_56(Parameter vctxt_6763, LogicalAndExpr target_56) {
		target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="73"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="71"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="78"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="79"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_56.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="82"
		and target_56.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_56.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_56.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_56.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="5"
		and target_56.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="69"
}

predicate func_57(Parameter vctxt_6763, ExprStmt target_57) {
		target_57.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_57.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6763
		and target_57.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_58(Parameter vctxt_6763, EqualityOperation target_58) {
		target_58.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_58.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_58.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6763
		and target_58.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vctxt_6763, FunctionCall target_0, FunctionCall target_1, FunctionCall target_2, FunctionCall target_3, FunctionCall target_4, FunctionCall target_5, FunctionCall target_6, FunctionCall target_7, FunctionCall target_8, FunctionCall target_10, FunctionCall target_12, FunctionCall target_13, FunctionCall target_14, FunctionCall target_15, FunctionCall target_16, FunctionCall target_18, FunctionCall target_20, FunctionCall target_21, FunctionCall target_22, FunctionCall target_23, FunctionCall target_24, FunctionCall target_25, FunctionCall target_27, FunctionCall target_29, FunctionCall target_30, FunctionCall target_31, FunctionCall target_32, FunctionCall target_33, FunctionCall target_34, FunctionCall target_35, FunctionCall target_36, FunctionCall target_38, FunctionCall target_40, FunctionCall target_41, FunctionCall target_42, FunctionCall target_43, EqualityOperation target_50, ExprStmt target_51, EqualityOperation target_52, EqualityOperation target_53, ExprStmt target_54, EqualityOperation target_55, LogicalAndExpr target_56, ExprStmt target_57, EqualityOperation target_58
where
func_0(vctxt_6763, target_0)
and func_1(vctxt_6763, target_1)
and func_2(vctxt_6763, target_2)
and func_3(vctxt_6763, target_3)
and func_4(vctxt_6763, target_4)
and func_5(vctxt_6763, target_5)
and func_6(vctxt_6763, target_6)
and func_7(vctxt_6763, target_7)
and func_8(vctxt_6763, target_8)
and func_10(vctxt_6763, target_10)
and func_12(func, target_12)
and func_13(vctxt_6763, target_13)
and func_14(vctxt_6763, target_14)
and func_15(vctxt_6763, target_15)
and func_16(vctxt_6763, target_16)
and func_18(vctxt_6763, target_18)
and func_20(func, target_20)
and func_21(vctxt_6763, target_21)
and func_22(vctxt_6763, target_22)
and func_23(vctxt_6763, target_23)
and func_24(vctxt_6763, target_24)
and func_25(vctxt_6763, target_25)
and func_27(vctxt_6763, target_27)
and func_29(func, target_29)
and func_30(vctxt_6763, target_30)
and func_31(vctxt_6763, target_31)
and func_32(vctxt_6763, target_32)
and func_33(vctxt_6763, target_33)
and func_34(vctxt_6763, target_34)
and func_35(vctxt_6763, target_35)
and func_36(vctxt_6763, target_36)
and func_38(vctxt_6763, target_38)
and func_40(func, target_40)
and func_41(vctxt_6763, target_41)
and func_42(vctxt_6763, target_42)
and func_43(vctxt_6763, target_43)
and not func_44(vctxt_6763, target_50, target_51, target_52)
and not func_45(target_50, func)
and not func_46(vctxt_6763, target_53, target_54, target_55)
and not func_47(target_53, func)
and not func_48(vctxt_6763, target_56, target_57, target_58)
and not func_49(target_56, func)
and func_50(vctxt_6763, target_50)
and func_51(vctxt_6763, target_51)
and func_52(vctxt_6763, target_52)
and func_53(vctxt_6763, target_53)
and func_54(vctxt_6763, target_54)
and func_55(vctxt_6763, target_55)
and func_56(vctxt_6763, target_56)
and func_57(vctxt_6763, target_57)
and func_58(vctxt_6763, target_58)
and vctxt_6763.getType().hasName("xmlParserCtxtPtr")
and vctxt_6763.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
