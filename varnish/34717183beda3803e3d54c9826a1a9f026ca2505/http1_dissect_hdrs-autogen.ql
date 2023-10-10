/**
 * @name varnish-34717183beda3803e3d54c9826a1a9f026ca2505-http1_dissect_hdrs
 * @id cpp/varnish/34717183beda3803e3d54c9826a1a9f026ca2505/http1-dissect-hdrs
 * @description varnish-34717183beda3803e3d54c9826a1a9f026ca2505-bin/varnishd/http1/cache_http1_proto.c-http1_dissect_hdrs CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="205"
		and target_0.getParent().(PointerAddExpr).getParent().(LEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vp_110, Parameter vhtc_110, ExprStmt target_15, LogicalAndExpr target_16) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getRValue().(FunctionCall).getTarget().hasName("vct_iscrlf")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_110
		and target_1.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_1.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_15.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable v__func__, ExprStmt target_18, Function func) {
	exists(DoStmt target_2 |
		target_2.getCondition() instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="i > 0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_2)
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_3(ExprStmt target_19, Function func) {
	exists(NotExpr target_3 |
		target_3.getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_3.getOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_19
		and target_3.getEnclosingFunction() = func)
}

*/
/*predicate func_4(Variable v__func__, ExprStmt target_18) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("VAS_Fail")
		and target_4.getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_4.getArgument(1) instanceof StringLiteral
		and target_4.getArgument(2) instanceof Literal
		and target_4.getArgument(3).(StringLiteral).getValue()="i > 0"
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_5(Parameter vp_110, LogicalAndExpr target_11, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_110
		and target_5.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_5)
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vhtc_110, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="rxbuf_e"
		and target_7.getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_8(Parameter vp_110, VariableAccess target_8) {
		target_8.getTarget()=vp_110
}

predicate func_11(Parameter vp_110, Parameter vhtc_110, ExprStmt target_19, LogicalAndExpr target_11) {
		target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_110
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_11.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="13"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_11.getParent().(IfStmt).getThen()=target_19
}

predicate func_13(Parameter vp_110, Parameter vhtc_110, LogicalAndExpr target_11, IfStmt target_13) {
		target_13.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_110
		and target_13.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_13.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_13.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_13.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_110
		and target_13.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_13.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_13.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_110
		and target_13.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="1"
		and target_13.getParent().(IfStmt).getCondition()=target_11
}

/*predicate func_14(Parameter vp_110, AssignPointerAddExpr target_14) {
		target_14.getLValue().(VariableAccess).getTarget()=vp_110
		and target_14.getRValue().(Literal).getValue()="1"
}

*/
predicate func_15(Parameter vp_110, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_15.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Too many headers: %.*s"
		and target_15.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_110
		and target_15.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="20"
		and target_15.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(Literal).getValue()="20"
		and target_15.getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_110
		and target_15.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vp_110
}

predicate func_16(Parameter vhtc_110, LogicalAndExpr target_16) {
		target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_16.getAnOperand().(FunctionCall).getTarget().hasName("vct_is")
		and target_16.getAnOperand().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="3"
}

predicate func_18(Variable v__func__, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_18.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_18.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_18.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="r < htc->rxbuf_e"
}

predicate func_19(Parameter vp_110, ExprStmt target_19) {
		target_19.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_110
		and target_19.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
}

from Function func, Parameter vp_110, Parameter vhtc_110, Variable v__func__, Literal target_0, PointerFieldAccess target_7, VariableAccess target_8, LogicalAndExpr target_11, IfStmt target_13, ExprStmt target_15, LogicalAndExpr target_16, ExprStmt target_18, ExprStmt target_19
where
func_0(func, target_0)
and not func_1(vp_110, vhtc_110, target_15, target_16)
and not func_2(v__func__, target_18, func)
and not func_5(vp_110, target_11, func)
and func_7(vhtc_110, target_7)
and func_8(vp_110, target_8)
and func_11(vp_110, vhtc_110, target_19, target_11)
and func_13(vp_110, vhtc_110, target_11, target_13)
and func_15(vp_110, target_15)
and func_16(vhtc_110, target_16)
and func_18(v__func__, target_18)
and func_19(vp_110, target_19)
and vp_110.getType().hasName("char *")
and vhtc_110.getType().hasName("http_conn *")
and v__func__.getType() instanceof ArrayType
and vp_110.getParentScope+() = func
and vhtc_110.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
