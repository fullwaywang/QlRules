/**
 * @name openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_parse_serverhello_tlsext
 * @id cpp/openssl/2b0532f3984324ebe1236a63d15893792384328d/ssl-parse-serverhello-tlsext
 * @description openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_parse_serverhello_tlsext CVE-2014-3513
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter val_1496, Variable vsize_1500, Variable vdata_1501, Parameter vs_1496) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1496
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="65279"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ssl_parse_serverhello_use_srtp_ext")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1496
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_1501
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_1500
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=val_1496
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter val_1496, Variable vtype_1499, Variable vsize_1500, Variable vdata_1501, Parameter vs_1496) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vtype_1499
		and target_1.getAnOperand().(Literal).getValue()="14"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ssl_parse_serverhello_use_srtp_ext")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1496
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_1501
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_1500
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=val_1496
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Parameter vs_1496) {
	exists(AssignOrExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_heartbeat"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1496
		and target_2.getRValue().(Literal).getValue()="2")
}

from Function func, Parameter val_1496, Variable vtype_1499, Variable vsize_1500, Variable vdata_1501, Parameter vs_1496
where
not func_0(val_1496, vsize_1500, vdata_1501, vs_1496)
and func_1(val_1496, vtype_1499, vsize_1500, vdata_1501, vs_1496)
and val_1496.getType().hasName("int *")
and vtype_1499.getType().hasName("unsigned short")
and vsize_1500.getType().hasName("unsigned short")
and vdata_1501.getType().hasName("unsigned char *")
and vs_1496.getType().hasName("SSL *")
and func_2(vs_1496)
and val_1496.getParentScope+() = func
and vtype_1499.getParentScope+() = func
and vsize_1500.getParentScope+() = func
and vdata_1501.getParentScope+() = func
and vs_1496.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
