/**
 * @name httpd-179492ff35adbc239c2fcdcb3d6af117a11c105b-ftp_getrc_msg
 * @id cpp/httpd/179492ff35adbc239c2fcdcb3d6af117a11c105b/ftp-getrc-msg
 * @description httpd-179492ff35adbc239c2fcdcb3d6af117a11c105b-modules/proxy/mod_proxy_ftp.c-ftp_getrc_msg CVE-2020-1934
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(VariableAccess).getType().hasName("apr_size_t")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_string_read")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("conn_rec *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("apr_bucket_brigade *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("char[80]")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="80"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vmb_386, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("apr_size_t")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_error_")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vmb_386
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getType().hasName("apr_size_t")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_string_read")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("conn_rec *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("apr_bucket_brigade *")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("char[80]")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="80"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getEnclosingFunction() = func)
}

from Function func, Variable vmb_386
where
not func_0(func)
and not func_1(vmb_386, func)
and not func_2(func)
and vmb_386.getType().hasName("char *")
and vmb_386.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
