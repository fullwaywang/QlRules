import cpp

predicate func_0(Parameter vdata) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("allow_auth_to_host")
		and target_0.getType().hasName("bool")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata)
}

predicate func_2(Variable vcompare, Variable vconn, Parameter vdata) {
	exists(LogicalAndExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="this_is_a_follow"
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(ValueFieldAccess).getType().hasName("bit")
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="first_host"
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(ValueFieldAccess).getType().hasName("char *")
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_2.getLeftOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_2.getLeftOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="allow_auth_to_other_hosts"
		and target_2.getLeftOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(ValueFieldAccess).getType().hasName("bit")
		and target_2.getLeftOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_2.getLeftOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_2.getRightOperand().(NotExpr).getType().hasName("int")
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_strcasecompare")
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="first_host"
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getType().hasName("char *")
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="name"
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getType().hasName("char *")
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="host"
		and target_2.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompare
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Authorization:"
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Authorization:"
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getType().hasName("int")
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcompare
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Cookie:"
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Cookie:"
		and target_2.getParent().(LogicalAndExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1")
}

from Function func, Variable vcompare, Variable vconn, Parameter vdata
where
not func_0(vdata)
and func_2(vcompare, vconn, vdata)
and vcompare.getType().hasName("char *")
and vconn.getType().hasName("connectdata *")
and vdata.getType().hasName("Curl_easy *")
and vcompare.getParentScope+() = func
and vconn.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vcompare, vconn, vdata
