/**
 * @name curl-364f174724ef115-pop3_state_capa_resp
 * @id cpp/curl/364f174724ef115/pop3-state-capa-resp
 * @description curl-364f174724ef115-pop3_state_capa_resp CVE-2021-22946
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpop3code_681) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vpop3code_681
		and target_0.getAnOperand().(CharLiteral).getValue()="43"
		and target_0.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_1(Variable vresult_684, Variable vconn_685, Parameter vdata_681) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(NotExpr).getOperand() instanceof ValueFieldAccess
		and target_1.getAnOperand() instanceof ValueFieldAccess
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_684
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_perform_authentication")
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_681
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_685)
}

predicate func_2(Function func) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand() instanceof ValueFieldAccess
		and target_2.getGreaterOperand() instanceof EnumConstantAccess
		and target_2.getParent().(IfStmt).getThen() instanceof ExprStmt
		and target_2.getEnclosingFunction() = func)
}

predicate func_6(Variable vresult_684, Variable vconn_685, Variable vpop3c_686, Parameter vdata_681) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="tls_supported"
		and target_6.getQualifier().(VariableAccess).getTarget()=vpop3c_686
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_684
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_perform_starttls")
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_681
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_685)
}

predicate func_8(Variable vresult_684, Variable vconn_685, Parameter vdata_681) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_684
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_perform_authentication")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_681
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_685
		and target_8.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_8.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_8.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_681
		and target_8.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="use"
		and target_8.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_8.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_685
		and target_8.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_9(Parameter vpop3code_681, Variable vpop3c_686) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="authtypes"
		and target_9.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpop3c_686
		and target_9.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="1"
		and target_9.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpop3code_681
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="43")
}

predicate func_11(Variable vresult_684, Variable vconn_685, Parameter vdata_681) {
	exists(EqualityOperation target_11 |
		target_11.getAnOperand() instanceof ValueFieldAccess
		and target_11.getAnOperand() instanceof EnumConstantAccess
		and target_11.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_684
		and target_11.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_perform_authentication")
		and target_11.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_681
		and target_11.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_685)
}

from Function func, Parameter vpop3code_681, Variable vresult_684, Variable vconn_685, Variable vpop3c_686, Parameter vdata_681
where
not func_0(vpop3code_681)
and not func_1(vresult_684, vconn_685, vdata_681)
and not func_2(func)
and func_6(vresult_684, vconn_685, vpop3c_686, vdata_681)
and func_8(vresult_684, vconn_685, vdata_681)
and func_9(vpop3code_681, vpop3c_686)
and func_11(vresult_684, vconn_685, vdata_681)
and vpop3code_681.getType().hasName("int")
and vresult_684.getType().hasName("CURLcode")
and vconn_685.getType().hasName("connectdata *")
and vpop3c_686.getType().hasName("pop3_conn *")
and vdata_681.getType().hasName("Curl_easy *")
and vpop3code_681.getParentScope+() = func
and vresult_684.getParentScope+() = func
and vconn_685.getParentScope+() = func
and vpop3c_686.getParentScope+() = func
and vdata_681.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
