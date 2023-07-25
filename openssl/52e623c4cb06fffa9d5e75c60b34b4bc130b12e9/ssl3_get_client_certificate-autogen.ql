/**
 * @name openssl-52e623c4cb06fffa9d5e75c60b34b4bc130b12e9-ssl3_get_client_certificate
 * @id cpp/openssl/52e623c4cb06fffa9d5e75c60b34b4bc130b12e9/ssl3-get-client-certificate
 * @description openssl-52e623c4cb06fffa9d5e75c60b34b4bc130b12e9-ssl/s3_srvr.c-ssl3_get_client_certificate CVE-2016-6306
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable val_3182, Variable vnc_3184, Variable vllen_3184, ExprStmt target_1, RelationalOperation target_2, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnc_3184
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vllen_3184
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_3182
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="f_err"
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_2.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable val_3182, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_3182
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
}

predicate func_2(Variable vnc_3184, Variable vllen_3184, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vnc_3184
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vllen_3184
}

predicate func_3(Variable vnc_3184, Variable vllen_3184, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnc_3184
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vllen_3184
}

from Function func, Variable val_3182, Variable vnc_3184, Variable vllen_3184, ExprStmt target_1, RelationalOperation target_2, RelationalOperation target_3
where
not func_0(val_3182, vnc_3184, vllen_3184, target_1, target_2, target_3)
and func_1(val_3182, target_1)
and func_2(vnc_3184, vllen_3184, target_2)
and func_3(vnc_3184, vllen_3184, target_3)
and val_3182.getType().hasName("int")
and vnc_3184.getType().hasName("unsigned long")
and vllen_3184.getType().hasName("unsigned long")
and val_3182.getParentScope+() = func
and vnc_3184.getParentScope+() = func
and vllen_3184.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
