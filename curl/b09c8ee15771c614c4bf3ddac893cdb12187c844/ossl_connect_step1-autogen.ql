import cpp

predicate func_3(Parameter vconn) {
	exists(ConditionalExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_3.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getType().hasName("int")
		and target_3.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_3.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(ValueFieldAccess).getType().hasName("curl_proxytype")
		and target_3.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_3.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getType().hasName("int")
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getType().hasName("ssl_connection_state")
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EQExpr).getRightOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_3.getThen().(Literal).getValue()="1"
		and target_3.getElse().(Literal).getValue()="0")
}

predicate func_4(Parameter vdata, Parameter vconn, Parameter vsockindex, Variable vbackend, Variable vdata_idx, Variable vconnectdata_idx, Variable vsockindex_idx) {
	exists(LogicalAndExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_4.getLeftOperand().(LogicalAndExpr).getLeftOperand().(GEExpr).getType().hasName("int")
		and target_4.getLeftOperand().(LogicalAndExpr).getLeftOperand().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vdata_idx
		and target_4.getLeftOperand().(LogicalAndExpr).getLeftOperand().(GEExpr).getLesserOperand().(Literal).getValue()="0"
		and target_4.getLeftOperand().(LogicalAndExpr).getRightOperand().(GEExpr).getType().hasName("int")
		and target_4.getLeftOperand().(LogicalAndExpr).getRightOperand().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vconnectdata_idx
		and target_4.getLeftOperand().(LogicalAndExpr).getRightOperand().(GEExpr).getLesserOperand().(Literal).getValue()="0"
		and target_4.getRightOperand().(GEExpr).getType().hasName("int")
		and target_4.getRightOperand().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vsockindex_idx
		and target_4.getRightOperand().(GEExpr).getLesserOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_idx
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconnectdata_idx
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vconn
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_set_ex_data")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handle"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbackend
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsockindex_idx
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerAddExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="sock"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerAddExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vsockindex)
}

from Function func, Parameter vdata, Parameter vconn, Parameter vsockindex, Variable vbackend, Variable vdata_idx, Variable vconnectdata_idx, Variable vsockindex_idx
where
not func_3(vconn)
and func_4(vdata, vconn, vsockindex, vbackend, vdata_idx, vconnectdata_idx, vsockindex_idx)
and vdata.getType().hasName("Curl_easy *")
and vconn.getType().hasName("connectdata *")
and vsockindex.getType().hasName("int")
and vbackend.getType().hasName("ssl_backend_data *")
and vdata_idx.getType().hasName("int")
and vconnectdata_idx.getType().hasName("int")
and vsockindex_idx.getType().hasName("int")
and vdata.getParentScope+() = func
and vconn.getParentScope+() = func
and vsockindex.getParentScope+() = func
and vbackend.getParentScope+() = func
and vdata_idx.getParentScope+() = func
and vconnectdata_idx.getParentScope+() = func
and vsockindex_idx.getParentScope+() = func
select func, vdata, vconn, vsockindex, vbackend, vdata_idx, vconnectdata_idx, vsockindex_idx
