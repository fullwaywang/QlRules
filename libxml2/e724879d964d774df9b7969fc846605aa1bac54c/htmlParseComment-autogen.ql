/**
 * @name libxml2-e724879d964d774df9b7969fc846605aa1bac54c-htmlParseComment
 * @id cpp/libxml2/e724879d964d774df9b7969fc846605aa1bac54c/htmlParseComment
 * @description libxml2-e724879d964d774df9b7969fc846605aa1bac54c-htmlParseComment CVE-2015-8710
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcur_3248) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vcur_3248
		and target_0.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="256")
}

predicate func_13(Variable vr_3247, Function func) {
	exists(IfStmt target_13 |
		target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_3247
		and target_13.getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111"
		and target_13.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_13))
}

predicate func_14(Variable vbuf_3243, Variable vlen_3244, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_3243
		and target_14.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_3244
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_14))
}

predicate func_15(Variable vbuf_3243, Variable vcur_3248, Variable vxmlFree, Function func) {
	exists(IfStmt target_15 |
		target_15.getCondition().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_15.getCondition().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_15.getCondition().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111"
		and target_15.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_15.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_15.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_15.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3243
		and target_15.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_15.getThen().(BlockStmt).getStmt(4) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_15))
}

predicate func_16(Function func) {
	exists(LabelStmt target_16 |
		target_16.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_16 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_16))
}

predicate func_17(Function func) {
	exists(ReturnStmt target_17 |
		target_17.toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_17 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_17))
}

predicate func_18(Parameter vctxt_3242, Variable vbuf_3243, Variable vcur_3248) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(FunctionCall).getTarget().hasName("htmlParseErr")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3242
		and target_18.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Comment not terminated \n<!--%.50s\n"
		and target_18.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_3243
		and target_18.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111")
}

predicate func_19(Parameter vctxt_3242, Variable vcur_3248) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3242
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111")
}

predicate func_20(Parameter vctxt_3242, Variable vbuf_3243, Variable vcur_3248) {
	exists(IfStmt target_20 |
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
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111")
}

predicate func_21(Variable vbuf_3243, Variable vcur_3248, Variable vxmlFree) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_21.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_3243
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getThen().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="55295"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="57344"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="65533"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65536"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_3248
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(ConditionalExpr).getElse().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1114111")
}

predicate func_22(Parameter vctxt_3242, Variable vstate_3249, Function func) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="instate"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3242
		and target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_3249
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22)
}

predicate func_24(Variable vbuf_3243, Variable vxmlFree) {
	exists(VariableCall target_24 |
		target_24.getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_24.getArgument(0).(VariableAccess).getTarget()=vbuf_3243)
}

predicate func_25(Variable vbuf_3243, Variable vlen_3244) {
	exists(ArrayExpr target_25 |
		target_25.getArrayBase().(VariableAccess).getTarget()=vbuf_3243
		and target_25.getArrayOffset().(VariableAccess).getTarget()=vlen_3244
		and target_25.getParent().(AssignExpr).getLValue() = target_25
		and target_25.getParent().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_26(Parameter vctxt_3242, Variable vr_3247, Variable vrl_3247) {
	exists(AssignExpr target_26 |
		target_26.getLValue().(VariableAccess).getTarget()=vr_3247
		and target_26.getRValue().(FunctionCall).getTarget().hasName("htmlCurrentChar")
		and target_26.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3242
		and target_26.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrl_3247)
}

from Function func, Parameter vctxt_3242, Variable vbuf_3243, Variable vlen_3244, Variable vr_3247, Variable vrl_3247, Variable vcur_3248, Variable vstate_3249, Variable vxmlFree
where
func_0(vcur_3248)
and not func_13(vr_3247, func)
and not func_14(vbuf_3243, vlen_3244, func)
and not func_15(vbuf_3243, vcur_3248, vxmlFree, func)
and not func_16(func)
and not func_17(func)
and func_18(vctxt_3242, vbuf_3243, vcur_3248)
and func_19(vctxt_3242, vcur_3248)
and func_20(vctxt_3242, vbuf_3243, vcur_3248)
and func_21(vbuf_3243, vcur_3248, vxmlFree)
and func_22(vctxt_3242, vstate_3249, func)
and vctxt_3242.getType().hasName("htmlParserCtxtPtr")
and vbuf_3243.getType().hasName("xmlChar *")
and func_24(vbuf_3243, vxmlFree)
and vlen_3244.getType().hasName("int")
and func_25(vbuf_3243, vlen_3244)
and vr_3247.getType().hasName("int")
and func_26(vctxt_3242, vr_3247, vrl_3247)
and vrl_3247.getType().hasName("int")
and vcur_3248.getType().hasName("int")
and vstate_3249.getType().hasName("xmlParserInputState")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vctxt_3242.getParentScope+() = func
and vbuf_3243.getParentScope+() = func
and vlen_3244.getParentScope+() = func
and vr_3247.getParentScope+() = func
and vrl_3247.getParentScope+() = func
and vcur_3248.getParentScope+() = func
and vstate_3249.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
