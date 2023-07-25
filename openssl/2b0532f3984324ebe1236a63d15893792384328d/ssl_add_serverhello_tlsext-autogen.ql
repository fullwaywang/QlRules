/**
 * @name openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_add_serverhello_tlsext
 * @id cpp/openssl/2b0532f3984324ebe1236a63d15893792384328d/ssl-add-serverhello-tlsext
 * @description openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_add_serverhello_tlsext CVE-2014-3513
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_702, Variable vel_811) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_702
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="65279"
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="srtp_profile"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_702
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl_add_serverhello_use_srtp_ext")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_702
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vel_811
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_1(Parameter vs_702, Variable vel_811) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="srtp_profile"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_702
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl_add_serverhello_use_srtp_ext")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_702
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vel_811
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_2(Parameter vs_702, Parameter vlimit_702, Variable vret_706, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="tlsext_status_expected"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_702
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_702
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vret_706
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="4"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vret_706
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vret_706
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter vs_702, Parameter vlimit_702, Variable vret_706, Variable vel_811
where
not func_0(vs_702, vel_811)
and func_1(vs_702, vel_811)
and vs_702.getType().hasName("SSL *")
and func_2(vs_702, vlimit_702, vret_706, func)
and vlimit_702.getType().hasName("unsigned char *")
and vret_706.getType().hasName("unsigned char *")
and vel_811.getType().hasName("int")
and vs_702.getParentScope+() = func
and vlimit_702.getParentScope+() = func
and vret_706.getParentScope+() = func
and vel_811.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
