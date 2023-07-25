/**
 * @name curl-364f174724ef115-imap_state_capability_resp
 * @id cpp/curl/364f174724ef115/imap-state-capability-resp
 * @description curl-364f174724ef115-imap_state_capability_resp CVE-2021-22946
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="STARTTLS not supported."
		and not target_0.getValue()="STARTTLS not available."
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vimapc_880) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof PointerFieldAccess
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="preauth"
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimapc_880
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt)
}

predicate func_2(Variable vresult_878, Variable vconn_879, Parameter vdata_874) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand() instanceof ValueFieldAccess
		and target_2.getGreaterOperand() instanceof EnumConstantAccess
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_878
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_perform_authentication")
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_874
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_879)
}

predicate func_3(Parameter vimapcode_875, Variable vresult_878, Variable vconn_879, Parameter vdata_874) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vimapcode_875
		and target_3.getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="use_ssl"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_874
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="use"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_879
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_878
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_perform_authentication")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_874
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_879)
}

predicate func_7(Parameter vdata_874) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="use_ssl"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_874)
}

predicate func_10(Variable vresult_878, Variable vconn_879, Parameter vdata_874) {
	exists(IfStmt target_10 |
		target_10.getCondition() instanceof PointerFieldAccess
		and target_10.getThen() instanceof ExprStmt
		and target_10.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof ValueFieldAccess
		and target_10.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_10.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_878
		and target_10.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_perform_authentication")
		and target_10.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_874
		and target_10.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_879
		and target_10.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_10.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_874
		and target_10.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_10.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_878
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalAndExpr)
}

predicate func_13(Variable vimapc_880) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="sasl"
		and target_13.getQualifier().(VariableAccess).getTarget()=vimapc_880)
}

from Function func, Parameter vimapcode_875, Variable vresult_878, Variable vconn_879, Variable vimapc_880, Parameter vdata_874
where
func_0(func)
and not func_1(vimapc_880)
and not func_2(vresult_878, vconn_879, vdata_874)
and func_3(vimapcode_875, vresult_878, vconn_879, vdata_874)
and func_7(vdata_874)
and func_10(vresult_878, vconn_879, vdata_874)
and vimapcode_875.getType().hasName("int")
and vresult_878.getType().hasName("CURLcode")
and vconn_879.getType().hasName("connectdata *")
and vimapc_880.getType().hasName("imap_conn *")
and func_13(vimapc_880)
and vdata_874.getType().hasName("Curl_easy *")
and vimapcode_875.getParentScope+() = func
and vresult_878.getParentScope+() = func
and vconn_879.getParentScope+() = func
and vimapc_880.getParentScope+() = func
and vdata_874.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
