/**
 * @name openssl-d81a1600588b726c2bdccda7efad3cc7a87d6245-get_client_hello
 * @id cpp/openssl/d81a1600588b726c2bdccda7efad3cc7a87d6245/get-client-hello
 * @description openssl-d81a1600588b726c2bdccda7efad3cc7a87d6245-get_client_hello CVE-2015-3197
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vprio_567, Variable vallow_567, Variable vz_568) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_ssl"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const SSL_CIPHER *")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vallow_567
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition() instanceof Literal
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getType().hasName("const SSL_CIPHER *")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse() instanceof Literal
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sk_delete")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vprio_567
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vz_568)
}

predicate func_3(Parameter vs_560) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("sk_num")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="ciphers"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_560
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_560
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hit"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_560)
}

predicate func_7(Variable vprio_567, Variable vz_568) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("sk_value")
		and target_7.getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_7.getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vprio_567
		and target_7.getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_7.getArgument(1).(VariableAccess).getTarget()=vz_568)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="1"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="0"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vallow_567) {
	exists(ConditionalExpr target_10 |
		target_10.getCondition() instanceof Literal
		and target_10.getThen() instanceof FunctionCall
		and target_10.getElse() instanceof Literal
		and target_10.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_10.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vallow_567
		and target_10.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0")
}

predicate func_11(Parameter vs_560, Variable vprio_567) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(PointerFieldAccess).getTarget().getName()="ciphers"
		and target_11.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_11.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_560
		and target_11.getRValue().(VariableAccess).getTarget()=vprio_567)
}

from Function func, Parameter vs_560, Variable vprio_567, Variable vallow_567, Variable vz_568
where
not func_0(func)
and not func_1(vprio_567, vallow_567, vz_568)
and not func_3(vs_560)
and func_7(vprio_567, vz_568)
and func_8(func)
and func_9(func)
and func_10(vallow_567)
and vs_560.getType().hasName("SSL *")
and func_11(vs_560, vprio_567)
and vprio_567.getType().hasName("stack_st_SSL_CIPHER *")
and vallow_567.getType().hasName("stack_st_SSL_CIPHER *")
and vz_568.getType().hasName("int")
and vs_560.getParentScope+() = func
and vprio_567.getParentScope+() = func
and vallow_567.getParentScope+() = func
and vz_568.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
