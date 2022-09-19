import cpp

predicate func_0(Parameter vdata) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("allow_auth_to_host")
		and target_0.getType().hasName("bool")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata)
}

predicate func_1(Parameter vconn) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="netrc"
		and target_1.getType().hasName("bit")
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_1.getQualifier().(PointerFieldAccess).getType().hasName("ConnectBits")
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn)
}

predicate func_2(Parameter vconn, Parameter vrequest, Parameter vpath, Variable vresult, Variable vauthhost, Parameter vdata) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getType().hasName("CURLcode")
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("output_auth_headers")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("CURLcode")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vauthhost
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vrequest
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpath
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand() instanceof LogicalOrExpr
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand() instanceof FunctionCall)
}

from Function func, Parameter vconn, Parameter vrequest, Parameter vpath, Variable vresult, Variable vauthhost, Parameter vdata
where
not func_0(vdata)
and func_1(vconn)
and func_2(vconn, vrequest, vpath, vresult, vauthhost, vdata)
and vconn.getType().hasName("connectdata *")
and vrequest.getType().hasName("const char *")
and vpath.getType().hasName("const char *")
and vresult.getType().hasName("CURLcode")
and vauthhost.getType().hasName("auth *")
and vdata.getType().hasName("Curl_easy *")
and vconn.getParentScope+() = func
and vrequest.getParentScope+() = func
and vpath.getParentScope+() = func
and vresult.getParentScope+() = func
and vauthhost.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vconn, vrequest, vpath, vresult, vauthhost, vdata
