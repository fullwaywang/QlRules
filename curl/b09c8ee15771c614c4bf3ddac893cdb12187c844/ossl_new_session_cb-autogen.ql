import cpp

predicate func_2(Variable vdata_idx, Variable vconnectdata_idx, Variable vsockindex_idx) {
	exists(LogicalOrExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vdata_idx
		and target_2.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vconnectdata_idx
		and target_2.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vsockindex_idx
		and target_2.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getRightOperand().(LTExpr).getType().hasName("int")
		and target_2.getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_7(Variable vconn, Variable vdata, Variable vsockindex, Variable vincache, Variable vold_ssl_sessionid) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getType().hasName("bool")
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vincache
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_ssl_getsessionid")
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getType().hasName("bool")
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vold_ssl_sessionid
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsockindex)
}

predicate func_9(Parameter vssl_sessionid, Variable vres, Variable vconn, Variable vdata, Variable vsockindex, Variable vincache) {
	exists(IfStmt target_9 |
		target_9.getCondition().(NotExpr).getType().hasName("int")
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_ssl_addsessionid")
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("CURLcode")
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vssl_sessionid
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_9.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsockindex
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="failed to store ssl session"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vincache)
}

predicate func_11(Variable vdata_idx, Variable vconnectdata_idx, Variable vsockindex_idx) {
	exists(LogicalOrExpr target_11 |
		target_11.getType().hasName("int")
		and target_11.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_11.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getType().hasName("int")
		and target_11.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vdata_idx
		and target_11.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_11.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getType().hasName("int")
		and target_11.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vconnectdata_idx
		and target_11.getLeftOperand().(LogicalOrExpr).getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_11.getRightOperand().(LTExpr).getType().hasName("int")
		and target_11.getRightOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vsockindex_idx
		and target_11.getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_11.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_12(Parameter vssl_sessionid, Variable vres, Variable vconn, Variable vdata, Variable vsockindex, Variable vincache) {
	exists(NotExpr target_12 |
		target_12.getType().hasName("int")
		and target_12.getOperand().(VariableAccess).getTarget()=vincache
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_ssl_addsessionid")
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vssl_sessionid
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsockindex
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="failed to store ssl session")
}

predicate func_14(Variable vconn, Variable vdata, Variable vsockindex, Variable vold_ssl_sessionid) {
	exists(VariableAccess target_14 |
		target_14.getParent().(AssignExpr).getRValue().(NotExpr).getType().hasName("int")
		and target_14.getParent().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_ssl_getsessionid")
		and target_14.getParent().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getType().hasName("bool")
		and target_14.getParent().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_14.getParent().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn
		and target_14.getParent().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vold_ssl_sessionid
		and target_14.getParent().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_14.getParent().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsockindex)
}

from Function func, Parameter vssl, Parameter vssl_sessionid, Variable vres, Variable vconn, Variable vdata, Variable vsockindex, Variable vdata_idx, Variable vconnectdata_idx, Variable vsockindex_idx, Variable vincache, Variable vold_ssl_sessionid
where
not func_2(vdata_idx, vconnectdata_idx, vsockindex_idx)
and not func_7(vconn, vdata, vsockindex, vincache, vold_ssl_sessionid)
and not func_9(vssl_sessionid, vres, vconn, vdata, vsockindex, vincache)
and func_11(vdata_idx, vconnectdata_idx, vsockindex_idx)
and func_12(vssl_sessionid, vres, vconn, vdata, vsockindex, vincache)
and func_14(vconn, vdata, vsockindex, vold_ssl_sessionid)
and vssl.getType().hasName("SSL *")
and vssl_sessionid.getType().hasName("SSL_SESSION *")
and vres.getType().hasName("int")
and vconn.getType().hasName("connectdata *")
and vdata.getType().hasName("Curl_easy *")
and vsockindex.getType().hasName("int")
and vdata_idx.getType().hasName("int")
and vconnectdata_idx.getType().hasName("int")
and vsockindex_idx.getType().hasName("int")
and vincache.getType().hasName("bool")
and vold_ssl_sessionid.getType().hasName("void *")
and vssl.getParentScope+() = func
and vssl_sessionid.getParentScope+() = func
and vres.getParentScope+() = func
and vconn.getParentScope+() = func
and vdata.getParentScope+() = func
and vsockindex.getParentScope+() = func
and vdata_idx.getParentScope+() = func
and vconnectdata_idx.getParentScope+() = func
and vsockindex_idx.getParentScope+() = func
and vincache.getParentScope+() = func
and vold_ssl_sessionid.getParentScope+() = func
select func, vssl, vssl_sessionid, vres, vconn, vdata, vsockindex, vdata_idx, vconnectdata_idx, vsockindex_idx, vincache, vold_ssl_sessionid
