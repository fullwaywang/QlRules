/**
 * @name openssl-52e623c4cb06fffa9d5e75c60b34b4bc130b12e9-ssl3_get_certificate_request
 * @id cpp/openssl/52e623c4cb06fffa9d5e75c60b34b4bc130b12e9/ssl3-get-certificate-request
 * @description openssl-52e623c4cb06fffa9d5e75c60b34b4bc130b12e9-ssl/s3_clnt.c-ssl3_get_certificate_request CVE-2016-6306
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1973, Variable vnc_1976, Variable vllen_1977, ExprStmt target_1, BitwiseAndExpr target_2, RelationalOperation target_3, RelationalOperation target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnc_1976
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vllen_1977
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl3_send_alert")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1973
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="50"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="err"
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_1973, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("ssl3_send_alert")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1973
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="50"
}

predicate func_2(Parameter vs_1973, BitwiseAndExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1973
		and target_2.getRightOperand().(Literal).getValue()="536870912"
}

predicate func_3(Variable vnc_1976, Variable vllen_1977, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vnc_1976
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vllen_1977
}

predicate func_4(Variable vnc_1976, Variable vllen_1977, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnc_1976
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vllen_1977
}

from Function func, Parameter vs_1973, Variable vnc_1976, Variable vllen_1977, ExprStmt target_1, BitwiseAndExpr target_2, RelationalOperation target_3, RelationalOperation target_4
where
not func_0(vs_1973, vnc_1976, vllen_1977, target_1, target_2, target_3, target_4)
and func_1(vs_1973, target_1)
and func_2(vs_1973, target_2)
and func_3(vnc_1976, vllen_1977, target_3)
and func_4(vnc_1976, vllen_1977, target_4)
and vs_1973.getType().hasName("SSL *")
and vnc_1976.getType().hasName("unsigned long")
and vllen_1977.getType().hasName("unsigned int")
and vs_1973.getParentScope+() = func
and vnc_1976.getParentScope+() = func
and vllen_1977.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
