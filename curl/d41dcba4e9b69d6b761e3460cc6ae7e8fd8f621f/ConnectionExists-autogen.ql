/**
 * @name curl-d41dcba4e9b69d6b761e3460cc6ae7e8fd8f621f-ConnectionExists
 * @id cpp/curl/d41dcba4e9b69d6b761e3460cc6ae7e8fd8f621f/ConnectionExists
 * @description curl-d41dcba4e9b69d6b761e3460cc6ae7e8fd8f621f-lib/url.c-ConnectionExists CVE-2016-0755
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_3121, ValueFieldAccess target_0) {
		target_0.getTarget().getName()="authhost"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3121
}

predicate func_1(Variable vcredentialsMatch_3192, BlockStmt target_31, ExprStmt target_29, IfStmt target_32, VariableAccess target_1) {
		target_1.getTarget()=vcredentialsMatch_3192
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_31
		and target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLocation())
		and target_1.getLocation().isBefore(target_32.getCondition().(VariableAccess).getLocation())
}

predicate func_2(Function func, Initializer target_2) {
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getExpr().getEnclosingFunction() = func
}

predicate func_3(Variable vcredentialsMatch_3192, ExprStmt target_30, VariableAccess target_3) {
		target_3.getTarget()=vcredentialsMatch_3192
		and target_3.getParent().(IfStmt).getThen()=target_30
}

predicate func_4(Function func) {
	exists(BitwiseOrExpr target_4 |
		target_4.getValue()="40"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vdata_3121, Parameter vneedle_3122, ValueFieldAccess target_33, LogicalAndExpr target_34, ValueFieldAccess target_35, EqualityOperation target_36) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(ValueFieldAccess).getTarget().getName()="proxy_user_passwd"
		and target_5.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_5.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="want"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="authproxy"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3121
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="40"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="protocol"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="3"
		and target_33.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_34.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_35.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_36.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_6(Function func) {
	exists(BitwiseOrExpr target_6 |
		target_6.getValue()="40"
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_7(Parameter vneedle_3122, Variable vcheck_3127, Variable vwantNTLMhttp_3132, BlockStmt target_37, LogicalOrExpr target_38, ExprStmt target_16) {
	exists(NotExpr target_7 |
		target_7.getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_7.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_7.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_7.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_7.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_7.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vwantNTLMhttp_3132
		and target_7.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_7.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_37
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vneedle_3122, Variable vcheck_3127, Variable vwantNTLMhttp_3132, BlockStmt target_37, LogicalOrExpr target_38) {
	exists(NotExpr target_8 |
		target_8.getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_8.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_8.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_8.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_8.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_8.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vwantNTLMhttp_3132
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_37
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(LogicalAndExpr target_41, Function func) {
	exists(ContinueStmt target_9 |
		target_9.toString() = "continue;"
		and target_9.getParent().(IfStmt).getCondition()=target_41
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vcheck_3127, VariableAccess target_42, ExprStmt target_30) {
	exists(IfStmt target_10 |
		target_10.getCondition().(VariableAccess).getType().hasName("bool")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="proxyuser"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="proxyuser"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="proxypasswd"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="proxypasswd"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_10.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_10.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proxyntlm"
		and target_10.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ContinueStmt).toString() = "continue;"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_10.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_11(Parameter vneedle_3122, Variable vcheck_3127, FunctionCall target_43) {
	exists(NotExpr target_11 |
		target_11.getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_11.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="proxyuser"
		and target_11.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_11.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="proxyuser"
		and target_11.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_43.getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_12(Parameter vneedle_3122, Variable vcheck_3127, ConditionalExpr target_28) {
	exists(NotExpr target_12 |
		target_12.getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_12.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="proxypasswd"
		and target_12.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_12.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="proxypasswd"
		and target_12.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_12.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_28.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_13(Variable vwantNTLMhttp_3132, VariableAccess target_42, IfStmt target_44) {
	exists(IfStmt target_13 |
		target_13.getCondition().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vwantNTLMhttp_3132
		and target_13.getCondition().(LogicalOrExpr).getAnOperand().(VariableAccess).getType().hasName("bool")
		and target_13.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("bool")
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("bool")
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_13.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof BreakStmt
		and target_13.getThen().(BlockStmt).getStmt(2).(ContinueStmt).toString() = "continue;"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_13.getCondition().(LogicalOrExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_44.getCondition().(VariableAccess).getLocation()))
}

/*predicate func_15(Variable vcheck_3127, EqualityOperation target_15) {
		target_15.getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ntlm"
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
}

*/
predicate func_16(Variable vcheck_3127, Variable vchosen_3128, LogicalAndExpr target_41, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchosen_3128
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcheck_3127
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
}

predicate func_17(Parameter vforce_reuse_3124, LogicalAndExpr target_41, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vforce_reuse_3124
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
}

predicate func_18(Function func, BinaryBitwiseOperation target_18) {
		target_18.getValue()="8"
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Function func, BinaryBitwiseOperation target_19) {
		target_19.getValue()="32"
		and target_19.getEnclosingFunction() = func
}

predicate func_20(Parameter vneedle_3122, Variable vcheck_3127, Variable vwantNTLMhttp_3132, BlockStmt target_37, NotExpr target_20) {
		target_20.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_20.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_20.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_20.getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="128"
		and target_20.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vwantNTLMhttp_3132
		and target_20.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_20.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ntlm"
		and target_20.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_20.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_37
}

predicate func_21(Variable vcheck_3127, Variable vcredentialsMatch_3192, BlockStmt target_31, EqualityOperation target_21) {
		target_21.getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_21.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ntlm"
		and target_21.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_21.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vcredentialsMatch_3192
		and target_21.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_31
}

predicate func_24(LogicalAndExpr target_41, Function func, BreakStmt target_24) {
		target_24.toString() = "break;"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_41
		and target_24.getEnclosingFunction() = func
}

predicate func_25(VariableAccess target_45, Function func, ContinueStmt target_25) {
		target_25.toString() = "continue;"
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
		and target_25.getEnclosingFunction() = func
}

predicate func_27(Variable vcheck_3127, Variable vchosen_3128, VariableAccess target_27) {
		target_27.getTarget()=vcheck_3127
		and target_27.getParent().(AssignExpr).getRValue() = target_27
		and target_27.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchosen_3128
}

predicate func_28(Parameter vneedle_3122, ConditionalExpr target_28) {
		target_28.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="want"
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="authhost"
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="want"
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="protocol"
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_28.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="3"
		and target_28.getThen() instanceof Literal
		and target_28.getElse() instanceof Literal
}

predicate func_29(Variable vcredentialsMatch_3192, LogicalOrExpr target_46, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcredentialsMatch_3192
		and target_29.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
}

predicate func_30(Variable vcheck_3127, Variable vchosen_3128, LogicalAndExpr target_41, ExprStmt target_16, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchosen_3128
		and target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcheck_3127
		and target_30.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_41
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_30.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_31(BlockStmt target_31) {
		target_31.getStmt(0) instanceof ExprStmt
		and target_31.getStmt(1) instanceof ExprStmt
		and target_31.getStmt(2) instanceof BreakStmt
}

predicate func_32(Variable vcredentialsMatch_3192, IfStmt target_32) {
		target_32.getCondition().(VariableAccess).getTarget()=vcredentialsMatch_3192
		and target_32.getThen() instanceof ExprStmt
}

predicate func_33(Parameter vdata_3121, ValueFieldAccess target_33) {
		target_33.getTarget().getName()="authhost"
		and target_33.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_33.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3121
}

predicate func_34(Parameter vdata_3121, Parameter vneedle_3122, LogicalAndExpr target_34) {
		target_34.getAnOperand().(FunctionCall).getTarget().hasName("Curl_pipeline_site_blacklisted")
		and target_34.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_3121
		and target_34.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vneedle_3122
}

predicate func_35(Parameter vneedle_3122, ValueFieldAccess target_35) {
		target_35.getTarget().getName()="name"
		and target_35.getQualifier().(PointerFieldAccess).getTarget().getName()="host"
		and target_35.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
}

predicate func_36(Parameter vneedle_3122, Variable vcheck_3127, EqualityOperation target_36) {
		target_36.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_36.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_36.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_36.getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_36.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_36.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="handler"
		and target_36.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_36.getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
}

predicate func_37(Parameter vneedle_3122, Variable vcheck_3127, BlockStmt target_37) {
		target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("curl_strequal")
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_37.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_37.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ContinueStmt).toString() = "continue;"
}

predicate func_38(Parameter vneedle_3122, Variable vcheck_3127, LogicalOrExpr target_38) {
		target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localport"
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localport"
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localportrange"
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="localportrange"
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="localdev"
		and target_38.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
		and target_38.getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_38.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="localdev"
		and target_38.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck_3127
		and target_38.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="localdev"
		and target_38.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_3122
}

predicate func_41(Variable vcredentialsMatch_3192, LogicalAndExpr target_41) {
		target_41.getAnOperand().(VariableAccess).getTarget()=vcredentialsMatch_3192
		and target_41.getAnOperand() instanceof EqualityOperation
}

predicate func_42(Variable vmatch_3190, VariableAccess target_42) {
		target_42.getTarget()=vmatch_3190
}

predicate func_43(Parameter vdata_3121, Parameter vneedle_3122, FunctionCall target_43) {
		target_43.getTarget().hasName("IsPipeliningPossible")
		and target_43.getArgument(0).(VariableAccess).getTarget()=vdata_3121
		and target_43.getArgument(1).(VariableAccess).getTarget()=vneedle_3122
}

predicate func_44(Variable vwantNTLMhttp_3132, Variable vcredentialsMatch_3192, IfStmt target_44) {
		target_44.getCondition().(VariableAccess).getTarget()=vwantNTLMhttp_3132
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vcredentialsMatch_3192
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof BreakStmt
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(VariableAccess).getTarget()=vcredentialsMatch_3192
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen() instanceof ExprStmt
}

predicate func_45(Variable vwantNTLMhttp_3132, VariableAccess target_45) {
		target_45.getTarget()=vwantNTLMhttp_3132
}

predicate func_46(Variable vwantNTLMhttp_3132, LogicalOrExpr target_46) {
		target_46.getAnOperand() instanceof NotExpr
		and target_46.getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vwantNTLMhttp_3132
		and target_46.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
}

from Function func, Parameter vdata_3121, Parameter vneedle_3122, Parameter vforce_reuse_3124, Variable vcheck_3127, Variable vchosen_3128, Variable vwantNTLMhttp_3132, Variable vmatch_3190, Variable vcredentialsMatch_3192, ValueFieldAccess target_0, VariableAccess target_1, Initializer target_2, VariableAccess target_3, ExprStmt target_16, ExprStmt target_17, BinaryBitwiseOperation target_18, BinaryBitwiseOperation target_19, NotExpr target_20, EqualityOperation target_21, BreakStmt target_24, ContinueStmt target_25, VariableAccess target_27, ConditionalExpr target_28, ExprStmt target_29, ExprStmt target_30, BlockStmt target_31, IfStmt target_32, ValueFieldAccess target_33, LogicalAndExpr target_34, ValueFieldAccess target_35, EqualityOperation target_36, BlockStmt target_37, LogicalOrExpr target_38, LogicalAndExpr target_41, VariableAccess target_42, FunctionCall target_43, IfStmt target_44, VariableAccess target_45, LogicalOrExpr target_46
where
func_0(vdata_3121, target_0)
and func_1(vcredentialsMatch_3192, target_31, target_29, target_32, target_1)
and func_2(func, target_2)
and func_3(vcredentialsMatch_3192, target_30, target_3)
and not func_4(func)
and not func_5(vdata_3121, vneedle_3122, target_33, target_34, target_35, target_36)
and not func_7(vneedle_3122, vcheck_3127, vwantNTLMhttp_3132, target_37, target_38, target_16)
and not func_8(vneedle_3122, vcheck_3127, vwantNTLMhttp_3132, target_37, target_38)
and not func_9(target_41, func)
and not func_10(vcheck_3127, target_42, target_30)
and not func_13(vwantNTLMhttp_3132, target_42, target_44)
and func_16(vcheck_3127, vchosen_3128, target_41, target_16)
and func_17(vforce_reuse_3124, target_41, target_17)
and func_18(func, target_18)
and func_19(func, target_19)
and func_20(vneedle_3122, vcheck_3127, vwantNTLMhttp_3132, target_37, target_20)
and func_21(vcheck_3127, vcredentialsMatch_3192, target_31, target_21)
and func_24(target_41, func, target_24)
and func_25(target_45, func, target_25)
and func_27(vcheck_3127, vchosen_3128, target_27)
and func_28(vneedle_3122, target_28)
and func_29(vcredentialsMatch_3192, target_46, target_29)
and func_30(vcheck_3127, vchosen_3128, target_41, target_16, target_30)
and func_31(target_31)
and func_32(vcredentialsMatch_3192, target_32)
and func_33(vdata_3121, target_33)
and func_34(vdata_3121, vneedle_3122, target_34)
and func_35(vneedle_3122, target_35)
and func_36(vneedle_3122, vcheck_3127, target_36)
and func_37(vneedle_3122, vcheck_3127, target_37)
and func_38(vneedle_3122, vcheck_3127, target_38)
and func_41(vcredentialsMatch_3192, target_41)
and func_42(vmatch_3190, target_42)
and func_43(vdata_3121, vneedle_3122, target_43)
and func_44(vwantNTLMhttp_3132, vcredentialsMatch_3192, target_44)
and func_45(vwantNTLMhttp_3132, target_45)
and func_46(vwantNTLMhttp_3132, target_46)
and vdata_3121.getType().hasName("SessionHandle *")
and vneedle_3122.getType().hasName("connectdata *")
and vforce_reuse_3124.getType().hasName("bool *")
and vcheck_3127.getType().hasName("connectdata *")
and vchosen_3128.getType().hasName("connectdata *")
and vwantNTLMhttp_3132.getType().hasName("bool")
and vmatch_3190.getType().hasName("bool")
and vcredentialsMatch_3192.getType().hasName("bool")
and vdata_3121.getParentScope+() = func
and vneedle_3122.getParentScope+() = func
and vforce_reuse_3124.getParentScope+() = func
and vcheck_3127.getParentScope+() = func
and vchosen_3128.getParentScope+() = func
and vwantNTLMhttp_3132.getParentScope+() = func
and vmatch_3190.getParentScope+() = func
and vcredentialsMatch_3192.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
