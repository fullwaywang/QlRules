/**
 * @name openssl-4040a7fd104b412bd446338c6c28a62eb7d8e852-get_client_hello
 * @id cpp/openssl/4040a7fd104b412bd446338c6c28a62eb7d8e852/get-client-hello
 * @description openssl-4040a7fd104b412bd446338c6c28a62eb7d8e852-ssl/s2_srvr.c-get_client_hello CVE-2015-3197
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vallow_567, BlockStmt target_7, ExprStmt target_8) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_ssl"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const SSL_CIPHER *")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vallow_567
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition() instanceof Literal
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getType().hasName("const SSL_CIPHER *")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse() instanceof Literal
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vallow_567) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition() instanceof Literal
		and target_1.getThen().(VariableAccess).getType().hasName("const SSL_CIPHER *")
		and target_1.getElse() instanceof Literal
		and target_1.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_1.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_1.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vallow_567
		and target_1.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1) instanceof ConditionalExpr)
}

*/
predicate func_2(Parameter vs_560, NotExpr target_9, ExprStmt target_10, PointerFieldAccess target_11) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("sk_num")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="ciphers"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_560
		and target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_560
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vprio_567, Variable vz_568, FunctionCall target_3) {
		target_3.getTarget().hasName("sk_value")
		and target_3.getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_3.getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vprio_567
		and target_3.getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_3.getArgument(1).(VariableAccess).getTarget()=vz_568
}

predicate func_6(Variable vallow_567, ConditionalExpr target_6) {
		target_6.getCondition() instanceof Literal
		and target_6.getThen() instanceof FunctionCall
		and target_6.getElse() instanceof Literal
		and target_6.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_6.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_6.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vallow_567
		and target_6.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_7(Variable vprio_567, Variable vz_568, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sk_delete")
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vprio_567
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vz_568
}

predicate func_8(Variable vallow_567, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vallow_567
}

predicate func_9(Parameter vs_560, NotExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="hit"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_560
}

predicate func_10(Parameter vs_560, Variable vprio_567, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ciphers"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_560
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vprio_567
}

predicate func_11(Parameter vs_560, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="tmp"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="s2"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_560
}

from Function func, Parameter vs_560, Variable vprio_567, Variable vallow_567, Variable vz_568, FunctionCall target_3, ConditionalExpr target_6, BlockStmt target_7, ExprStmt target_8, NotExpr target_9, ExprStmt target_10, PointerFieldAccess target_11
where
not func_0(vallow_567, target_7, target_8)
and not func_2(vs_560, target_9, target_10, target_11)
and func_3(vprio_567, vz_568, target_3)
and func_6(vallow_567, target_6)
and func_7(vprio_567, vz_568, target_7)
and func_8(vallow_567, target_8)
and func_9(vs_560, target_9)
and func_10(vs_560, vprio_567, target_10)
and func_11(vs_560, target_11)
and vs_560.getType().hasName("SSL *")
and vprio_567.getType().hasName("stack_st_SSL_CIPHER *")
and vallow_567.getType().hasName("stack_st_SSL_CIPHER *")
and vz_568.getType().hasName("int")
and vs_560.getParentScope+() = func
and vprio_567.getParentScope+() = func
and vallow_567.getParentScope+() = func
and vz_568.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
