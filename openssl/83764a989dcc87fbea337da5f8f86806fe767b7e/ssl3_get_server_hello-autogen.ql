/**
 * @name openssl-83764a989dcc87fbea337da5f8f86806fe767b7e-ssl3_get_server_hello
 * @id cpp/openssl/83764a989dcc87fbea337da5f8f86806fe767b7e/ssl3-get-server-hello
 * @description openssl-83764a989dcc87fbea337da5f8f86806fe767b7e-ssl3_get_server_hello CVE-2014-5139
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_820, Variable vc_823, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_mkey"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_823
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_auth"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_823
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="srp_Mask"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="srp_ctx"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_820
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_0))
}

predicate func_4(Variable vi_825, Variable val_825) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_825
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="47"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_825
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_8(Parameter vs_820, Variable vc_823, Variable val_825) {
	exists(LogicalAndExpr target_8 |
		target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_ssl"
		and target_8.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_823
		and target_8.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_820
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="version"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_820
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="771"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_825
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="47"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Parameter vs_820, Variable vc_823, Variable vi_825, Variable val_825, Variable vj_826, Variable vcomp_829
where
not func_0(vs_820, vc_823, func)
and func_4(vi_825, val_825)
and vs_820.getType().hasName("SSL *")
and func_8(vs_820, vc_823, val_825)
and vc_823.getType().hasName("const SSL_CIPHER *")
and vi_825.getType().hasName("int")
and val_825.getType().hasName("int")
and vj_826.getType().hasName("unsigned int")
and vcomp_829.getType().hasName("SSL_COMP *")
and vs_820.getParentScope+() = func
and vc_823.getParentScope+() = func
and vi_825.getParentScope+() = func
and val_825.getParentScope+() = func
and vj_826.getParentScope+() = func
and vcomp_829.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
