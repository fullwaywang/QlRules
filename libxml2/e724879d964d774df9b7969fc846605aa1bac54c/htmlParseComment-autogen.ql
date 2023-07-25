/**
 * @name libxml2-e724879d964d774df9b7969fc846605aa1bac54c-htmlParseComment
 * @id cpp/libxml2/e724879d964d774df9b7969fc846605aa1bac54c/htmlParseComment
 * @description libxml2-e724879d964d774df9b7969fc846605aa1bac54c-HTMLparser.c-htmlParseComment CVE-2015-8710
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcur_3248, ExprStmt target_25, VariableAccess target_0) {
		target_0.getTarget()=vcur_3248
		and target_0.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="256"
		and target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Variable vcur_3248, VariableAccess target_1) {
		target_1.getTarget()=vcur_3248
}

predicate func_2(Variable vcur_3248, VariableAccess target_2) {
		target_2.getTarget()=vcur_3248
}

predicate func_3(Variable vcur_3248, VariableAccess target_3) {
		target_3.getTarget()=vcur_3248
}

predicate func_4(Variable vcur_3248, VariableAccess target_4) {
		target_4.getTarget()=vcur_3248
}

predicate func_5(Variable vcur_3248, VariableAccess target_5) {
		target_5.getTarget()=vcur_3248
}

predicate func_6(Variable vcur_3248, VariableAccess target_6) {
		target_6.getTarget()=vcur_3248
}

predicate func_7(Variable vcur_3248, VariableAccess target_7) {
		target_7.getTarget()=vcur_3248
}

predicate func_8(Variable vcur_3248, VariableAccess target_8) {
		target_8.getTarget()=vcur_3248
}

predicate func_9(Variable vcur_3248, VariableAccess target_9) {
		target_9.getTarget()=vcur_3248
}

predicate func_10(Variable vcur_3248, VariableAccess target_10) {
		target_10.getTarget()=vcur_3248
}

predicate func_11(Variable vbuf_3243, Variable vlen_3244, EqualityOperation target_26, ExprStmt target_27, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_3243
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_3244
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_11)
		and target_26.getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_12(Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_12.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_12))
}

/*predicate func_13(BlockStmt target_28, Function func) {
	exists(ConditionalExpr target_13 |
		target_13.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_13.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_13.getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_13.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111"
		and target_13.getParent().(NotExpr).getOperand() instanceof ConditionalExpr
		and target_13.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_28
		and target_13.getEnclosingFunction() = func)
}

*/
predicate func_14(Variable vr_3247, ExprStmt target_29, LogicalAndExpr target_30, Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_3247
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vr_3247
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_3247
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_3247
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_3247
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_14)
		and target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_14.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_15(Function func) {
	exists(LabelStmt target_15 |
		(func.getEntryPoint().(BlockStmt).getStmt(26)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_15))
}

predicate func_17(Parameter vctxt_3242, Variable vbuf_3243, NotExpr target_31, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("htmlParseErr")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3242
		and target_17.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Comment not terminated \n<!--%.50s\n"
		and target_17.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_3243
		and target_17.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
}

predicate func_18(Variable vbuf_3243, Variable vxmlFree, NotExpr target_31, ExprStmt target_18) {
		target_18.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_18.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3243
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
}

predicate func_19(Parameter vctxt_3242, NotExpr target_31, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3242
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
}

predicate func_20(Parameter vctxt_3242, Variable vbuf_3243, NotExpr target_31, IfStmt target_20) {
		target_20.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sax"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3242
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="comment"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3242
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="disableSAX"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3242
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="comment"
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3242
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3242
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vbuf_3243
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
}

predicate func_21(Variable vbuf_3243, Variable vxmlFree, NotExpr target_31, ExprStmt target_21) {
		target_21.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_21.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3243
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
}

predicate func_22(Parameter vctxt_3242, Variable vstate_3249, Function func, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="instate"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3242
		and target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_3249
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
}

predicate func_23(Variable vcur_3248, BlockStmt target_28, ConditionalExpr target_23) {
		target_23.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_23.getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_23.getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111"
		and target_23.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_28
}

predicate func_24(Function func, ReturnStmt target_24) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_24
}

predicate func_25(Parameter vctxt_3242, Variable vcur_3248, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_3248
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("htmlCurrentChar")
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3242
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_26(Variable vbuf_3243, EqualityOperation target_26) {
		target_26.getAnOperand().(VariableAccess).getTarget()=vbuf_3243
		and target_26.getAnOperand().(Literal).getValue()="0"
}

predicate func_27(Variable vbuf_3243, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_27.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget().getType().hasName("xmlReallocFunc")
		and target_27.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3243
		and target_27.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_27.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_27.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
}

predicate func_28(BlockStmt target_28) {
		target_28.getStmt(0) instanceof ExprStmt
		and target_28.getStmt(1) instanceof ExprStmt
}

predicate func_29(Parameter vctxt_3242, Variable vr_3247, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_3247
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("htmlCurrentChar")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3242
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_30(Variable vr_3247, Variable vcur_3248, LogicalAndExpr target_30) {
		target_30.getAnOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_30.getAnOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="62"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vr_3247
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
}

predicate func_31(NotExpr target_31) {
		target_31.getOperand() instanceof ConditionalExpr
}

from Function func, Parameter vctxt_3242, Variable vbuf_3243, Variable vlen_3244, Variable vr_3247, Variable vcur_3248, Variable vstate_3249, Variable vxmlFree, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, IfStmt target_20, ExprStmt target_21, ExprStmt target_22, ConditionalExpr target_23, ReturnStmt target_24, ExprStmt target_25, EqualityOperation target_26, ExprStmt target_27, BlockStmt target_28, ExprStmt target_29, LogicalAndExpr target_30, NotExpr target_31
where
func_0(vcur_3248, target_25, target_0)
and func_1(vcur_3248, target_1)
and func_2(vcur_3248, target_2)
and func_3(vcur_3248, target_3)
and func_4(vcur_3248, target_4)
and func_5(vcur_3248, target_5)
and func_6(vcur_3248, target_6)
and func_7(vcur_3248, target_7)
and func_8(vcur_3248, target_8)
and func_9(vcur_3248, target_9)
and func_10(vcur_3248, target_10)
and not func_11(vbuf_3243, vlen_3244, target_26, target_27, func)
and not func_12(func)
and not func_14(vr_3247, target_29, target_30, func)
and not func_15(func)
and func_17(vctxt_3242, vbuf_3243, target_31, target_17)
and func_18(vbuf_3243, vxmlFree, target_31, target_18)
and func_19(vctxt_3242, target_31, target_19)
and func_20(vctxt_3242, vbuf_3243, target_31, target_20)
and func_21(vbuf_3243, vxmlFree, target_31, target_21)
and func_22(vctxt_3242, vstate_3249, func, target_22)
and func_23(vcur_3248, target_28, target_23)
and func_24(func, target_24)
and func_25(vctxt_3242, vcur_3248, target_25)
and func_26(vbuf_3243, target_26)
and func_27(vbuf_3243, target_27)
and func_28(target_28)
and func_29(vctxt_3242, vr_3247, target_29)
and func_30(vr_3247, vcur_3248, target_30)
and func_31(target_31)
and vctxt_3242.getType().hasName("htmlParserCtxtPtr")
and vbuf_3243.getType().hasName("xmlChar *")
and vlen_3244.getType().hasName("int")
and vr_3247.getType().hasName("int")
and vcur_3248.getType().hasName("int")
and vstate_3249.getType().hasName("xmlParserInputState")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vctxt_3242.getFunction() = func
and vbuf_3243.(LocalVariable).getFunction() = func
and vlen_3244.(LocalVariable).getFunction() = func
and vr_3247.(LocalVariable).getFunction() = func
and vcur_3248.(LocalVariable).getFunction() = func
and vstate_3249.(LocalVariable).getFunction() = func
and not vxmlFree.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
