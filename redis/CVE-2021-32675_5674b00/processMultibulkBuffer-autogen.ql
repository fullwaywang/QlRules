/**
 * @name redis-5674b0057ff2903d43eaff802017eddf37c360f8-processMultibulkBuffer
 * @id cpp/redis/5674b0057ff2903d43eaff802017eddf37c360f8/processMultibulkBuffer
 * @description redis-5674b0057ff2903d43eaff802017eddf37c360f8-src/networking.c-processMultibulkBuffer CVE-2021-32675
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_1716, Variable vll_1719, LogicalOrExpr target_2, ExprStmt target_3, ExprStmt target_4, RelationalOperation target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vll_1719
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("authRequired")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1716
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1716
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Protocol error: unauthenticated multibulk length"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("setProtocolError")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="unauth mbulk count"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_1716
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_1716, Variable vll_1719, LogicalOrExpr target_6, ExprStmt target_7, ExprStmt target_8, RelationalOperation target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vll_1719
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="16384"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("authRequired")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1716
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1716
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Protocol error: unauthenticated bulk length"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("setProtocolError")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="unauth bulk length"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_1716
		and target_1.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(IfStmt).getCondition()=target_6
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vll_1719, LogicalOrExpr target_2) {
		target_2.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vll_1719
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="1048576"
}

predicate func_3(Parameter vc_1716, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("setProtocolError")
		and target_3.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="invalid mbulk count"
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_1716
}

predicate func_4(Parameter vc_1716, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="qb_pos"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1716
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="querybuf"
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1716
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_5(Variable vll_1719, RelationalOperation target_5) {
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vll_1719
		and target_5.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_6(Parameter vc_1716, Variable vll_1719, LogicalOrExpr target_6) {
		target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vll_1719
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1716
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vll_1719
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="proto_max_bulk_len"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("redisServer")
}

predicate func_7(Parameter vc_1716, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("setProtocolError")
		and target_7.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="invalid bulk length"
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc_1716
}

predicate func_8(Parameter vc_1716, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="qb_pos"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1716
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="querybuf"
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1716
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_9(Variable vll_1719, RelationalOperation target_9) {
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vll_1719
		and target_9.getLesserOperand().(MulExpr).getValue()="32768"
}

from Function func, Parameter vc_1716, Variable vll_1719, LogicalOrExpr target_2, ExprStmt target_3, ExprStmt target_4, RelationalOperation target_5, LogicalOrExpr target_6, ExprStmt target_7, ExprStmt target_8, RelationalOperation target_9
where
not func_0(vc_1716, vll_1719, target_2, target_3, target_4, target_5)
and not func_1(vc_1716, vll_1719, target_6, target_7, target_8, target_9)
and func_2(vll_1719, target_2)
and func_3(vc_1716, target_3)
and func_4(vc_1716, target_4)
and func_5(vll_1719, target_5)
and func_6(vc_1716, vll_1719, target_6)
and func_7(vc_1716, target_7)
and func_8(vc_1716, target_8)
and func_9(vll_1719, target_9)
and vc_1716.getType().hasName("client *")
and vll_1719.getType().hasName("long long")
and vc_1716.getFunction() = func
and vll_1719.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
