/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-xaddCommand
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/xaddCommand
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/t_stream.c-xaddCommand CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_1195, EqualityOperation target_2, DivExpr target_3, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="33"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1195
		and target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Elements are too large to be stored"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_1195, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1195
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="The ID specified in XADD is equal or smaller than the target stream top item"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vc_1195, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("streamAppendItem")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("stream *")
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="argv"
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1195
		and target_2.getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(FunctionCall).getArgument(2).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_2.getAnOperand().(FunctionCall).getArgument(2).(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1195
		and target_2.getAnOperand().(FunctionCall).getArgument(2).(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(FunctionCall).getArgument(2).(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("streamID")
		and target_2.getAnOperand().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("streamID")
		and target_2.getAnOperand().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_2.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_3(Parameter vc_1195, DivExpr target_3) {
		target_3.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_3.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1195
		and target_3.getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vc_1195, ExprStmt target_1, EqualityOperation target_2, DivExpr target_3
where
not func_0(vc_1195, target_2, target_3, target_1)
and func_1(vc_1195, target_2, target_1)
and func_2(vc_1195, target_2)
and func_3(vc_1195, target_3)
and vc_1195.getType().hasName("client *")
and vc_1195.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
