import cpp

predicate func_0(Parameter vdata, Parameter vconn, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("Curl_ssl_associate_conn")
		and target_0.getExpr().(FunctionCall).getType().hasName("void")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vdata, Parameter vconn
where
not func_0(vdata, vconn, func)
and vdata.getType().hasName("Curl_easy *")
and vconn.getType().hasName("connectdata *")
and vdata.getParentScope+() = func
and vconn.getParentScope+() = func
select func, vdata, vconn
