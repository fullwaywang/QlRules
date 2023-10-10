/**
 * @name httpd-0c543e3f5b3881d515d6235f152aacaaaf3aba72-uwsgi_send_headers
 * @id cpp/httpd/0c543e3f5b3881d515d6235f152aacaaaf3aba72/uwsgi-send-headers
 * @description httpd-0c543e3f5b3881d515d6235f152aacaaaf3aba72-modules/proxy/mod_proxy_uwsgi.c-uwsgi_send_headers CVE-2020-11984
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Variable vpktsize_139, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpktsize_139
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="65535"
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="500"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_3))
}

from Function func, Variable vpktsize_139
where
not func_3(vpktsize_139, func)
and vpktsize_139.getType().hasName("apr_uint16_t")
and vpktsize_139.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
