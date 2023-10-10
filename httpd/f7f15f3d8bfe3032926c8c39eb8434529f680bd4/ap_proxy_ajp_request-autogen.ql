/**
 * @name httpd-f7f15f3d8bfe3032926c8c39eb8434529f680bd4-ap_proxy_ajp_request
 * @id cpp/httpd/f7f15f3d8bfe3032926c8c39eb8434529f680bd4/ap-proxy-ajp-request
 * @description httpd-f7f15f3d8bfe3032926c8c39eb8434529f680bd4-modules/proxy/mod_proxy_ajp.c-ap_proxy_ajp_request CVE-2022-26377
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(LogicalAndExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof EqualityOperation
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_0.getElse().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_0.getElse().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="500"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vtenc_175, BlockStmt target_4, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmp")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtenc_175
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunked"
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vtenc_175
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

/*predicate func_2(Variable vtenc_175, BlockStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vtenc_175
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ap_cstr_casecmp")
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtenc_175
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="chunked"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

*/
predicate func_3(Variable vtenc_175, LogicalAndExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vtenc_175
		and target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof DoStmt
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getValue()="0"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="7"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("request_rec *")
		and target_4.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="AH00870: request is chunked"
}

from Function func, Variable vtenc_175, EqualityOperation target_1, LogicalAndExpr target_3, BlockStmt target_4
where
not func_0(target_3, func)
and func_1(vtenc_175, target_4, target_1)
and func_3(vtenc_175, target_3)
and func_4(target_4)
and vtenc_175.getType().hasName("const char *")
and vtenc_175.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
