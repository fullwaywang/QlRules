/**
 * @name openssl-98ece4eebfb6cd45cc8d550c6ac0022965071afc-ssl3_get_new_session_ticket
 * @id cpp/openssl/98ece4eebfb6cd45cc8d550c6ac0022965071afc/ssl3-get-new-session-ticket
 * @description openssl-98ece4eebfb6cd45cc8d550c6ac0022965071afc-ssl/s3_clnt.c-ssl3_get_new_session_ticket CVE-2015-1791
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_2218, Variable val_2220, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="session_id_length"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("SSL_SESSION *")
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ssl_session_dup")
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_2220
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="f_err"
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_SESSION_free")
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218
		and target_0.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("SSL_SESSION *")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_2218, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="init_msg"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218
}

predicate func_2(Parameter vs_2218, ExprStmt target_2) {
		target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_tick_lifetime_hint"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_tick_lifetime_hint"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_tick_lifetime_hint"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218
		and target_2.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_2.getExpr().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_tick_lifetime_hint"
		and target_2.getExpr().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getExpr().(CommaExpr).getRightOperand().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218
}

predicate func_3(Variable val_2220, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_2220
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
}

from Function func, Parameter vs_2218, Variable val_2220, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vs_2218, val_2220, target_1, target_2, target_3, func)
and func_1(vs_2218, target_1)
and func_2(vs_2218, target_2)
and func_3(val_2220, target_3)
and vs_2218.getType().hasName("SSL *")
and val_2220.getType().hasName("int")
and vs_2218.getParentScope+() = func
and val_2220.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
