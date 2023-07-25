/**
 * @name libxml2-0bcd05c5cd83dec3406c8f68b769b1d610c72f76-xmlNextChar
 * @id cpp/libxml2/0bcd05c5cd83dec3406c8f68b769b1d610c72f76/xmlNextChar
 * @description libxml2-0bcd05c5cd83dec3406c8f68b769b1d610c72f76-parserInternals.c-xmlNextChar CVE-2016-1833
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_419, BlockStmt target_15, LogicalOrExpr target_16, EqualityOperation target_8) {
	exists(NotExpr target_0 |
		target_0.getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_0.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_0.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_0.getParent().(IfStmt).getThen()=target_15
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_419, EqualityOperation target_8) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("xmlErrInternal")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_419
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Parser input data memory error\n"
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8)
}

predicate func_2(Parameter vctxt_419, EqualityOperation target_8) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="errNo"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8)
}

predicate func_3(Parameter vctxt_419, EqualityOperation target_8, LogicalAndExpr target_14) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("xmlStopParser")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_419
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8)
}

predicate func_4(EqualityOperation target_8, Function func) {
	exists(ReturnStmt target_4 |
		target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition() instanceof LogicalAndExpr
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof EqualityOperation
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_5))
}

/*predicate func_6(LogicalAndExpr target_14, Function func) {
	exists(ReturnStmt target_6 |
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_7(Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition() instanceof EqualityOperation
		and target_7.getThen() instanceof BlockStmt
		and target_7.getElse() instanceof BlockStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_7))
}

predicate func_8(Parameter vctxt_419, BlockStmt target_15, EqualityOperation target_8) {
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="charset"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_8.getParent().(IfStmt).getThen()=target_15
}

predicate func_9(Parameter vctxt_419, BlockStmt target_17, LogicalAndExpr target_9) {
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("xmlParserInputGrow")
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(Literal).getValue()="250"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_9.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_17
}

/*predicate func_10(Parameter vctxt_419, BlockStmt target_17, EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("xmlParserInputGrow")
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(Literal).getValue()="250"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_17
}

*/
predicate func_11(Parameter vctxt_419, LogicalAndExpr target_14, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("xmlPopInput")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_419
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_12(Variable vcur_437, Variable vc_438, Parameter vctxt_419, LogicalAndExpr target_14, BlockStmt target_12) {
		target_12.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_12.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_12.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_12.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="line"
		and target_12.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_12.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_12.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="col"
		and target_12.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(2).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_12.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_437
		and target_12.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_12.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_12.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_438
		and target_12.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcur_437
		and target_12.getStmt(5).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vc_438
		and target_12.getStmt(5).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="128"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_438
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="192"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcur_437
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserInputGrow")
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="192"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="128"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vc_438
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="224"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="224"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getElse().(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_12.getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getElse().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_12.getStmt(5).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_12.getStmt(5).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(5).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_12.getStmt(6).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nbChars"
		and target_12.getStmt(6).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_12.getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_12.getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_12.getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getStmt(7).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserInputGrow")
		and target_12.getStmt(7).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_12.getStmt(7).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_12.getStmt(7).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="250"
		and target_12.getParent().(IfStmt).getCondition()=target_14
}

predicate func_13(Parameter vctxt_419, EqualityOperation target_8, BlockStmt target_13) {
		target_13.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_13.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_13.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_13.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="line"
		and target_13.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_13.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_13.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="col"
		and target_13.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_13.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_13.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_13.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nbChars"
		and target_13.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_13.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_13.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_13.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlParserInputGrow")
		and target_13.getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_13.getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="250"
		and target_13.getParent().(IfStmt).getCondition()=target_8
}

predicate func_14(BlockStmt target_17, Function func, LogicalAndExpr target_14) {
		target_14.getAnOperand() instanceof LogicalAndExpr
		and target_14.getAnOperand() instanceof EqualityOperation
		and target_14.getParent().(IfStmt).getThen()=target_17
		and target_14.getEnclosingFunction() = func
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(0).(IfStmt).getCondition() instanceof LogicalAndExpr
		and target_15.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_15.getStmt(0).(IfStmt).getElse() instanceof BlockStmt
}

predicate func_16(Parameter vctxt_419, LogicalOrExpr target_16) {
		target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vctxt_419
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_419
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0) instanceof ExprStmt
}

from Function func, Variable vcur_437, Variable vc_438, Parameter vctxt_419, EqualityOperation target_8, LogicalAndExpr target_9, ExprStmt target_11, BlockStmt target_12, BlockStmt target_13, LogicalAndExpr target_14, BlockStmt target_15, LogicalOrExpr target_16, BlockStmt target_17
where
not func_0(vctxt_419, target_15, target_16, target_8)
and not func_1(vctxt_419, target_8)
and not func_2(vctxt_419, target_8)
and not func_3(vctxt_419, target_8, target_14)
and not func_4(target_8, func)
and not func_5(func)
and not func_7(func)
and func_8(vctxt_419, target_15, target_8)
and func_9(vctxt_419, target_17, target_9)
and func_11(vctxt_419, target_14, target_11)
and func_12(vcur_437, vc_438, vctxt_419, target_14, target_12)
and func_13(vctxt_419, target_8, target_13)
and func_14(target_17, func, target_14)
and func_15(target_15)
and func_16(vctxt_419, target_16)
and func_17(target_17)
and vcur_437.getType().hasName("const unsigned char *")
and vc_438.getType().hasName("unsigned char")
and vctxt_419.getType().hasName("xmlParserCtxtPtr")
and vcur_437.(LocalVariable).getFunction() = func
and vc_438.(LocalVariable).getFunction() = func
and vctxt_419.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
