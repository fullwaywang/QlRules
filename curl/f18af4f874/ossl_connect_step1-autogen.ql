/**
 * @name curl-f18af4f874-ossl_connect_step1
 * @id cpp/curl/f18af4f874/ossl-connect-step1
 * @description curl-f18af4f874-ossl_connect_step1 CVE-2022-27782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_6(Variable vssl_authtype_2665, Parameter vconn_2642, Parameter vdata_2641) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="proxytype"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2642
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2642
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2642
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(ValueFieldAccess).getTarget().getName()="password"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="password"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vssl_authtype_2665
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_allow_auth_to_host")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_2641)
}

predicate func_10(Parameter vdata_2641) {
	exists(ValueFieldAccess target_10 |
		target_10.getTarget().getName()="proxy_ssl"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2641)
}

predicate func_11(Parameter vdata_2641) {
	exists(ValueFieldAccess target_11 |
		target_11.getTarget().getName()="ssl"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2641)
}

from Function func, Variable vssl_authtype_2665, Parameter vconn_2642, Parameter vdata_2641
where
not func_6(vssl_authtype_2665, vconn_2642, vdata_2641)
and func_10(vdata_2641)
and func_11(vdata_2641)
and vssl_authtype_2665.getType().hasName("const CURL_TLSAUTH")
and vconn_2642.getType().hasName("connectdata *")
and vdata_2641.getType().hasName("Curl_easy *")
and vssl_authtype_2665.getParentScope+() = func
and vconn_2642.getParentScope+() = func
and vdata_2641.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
