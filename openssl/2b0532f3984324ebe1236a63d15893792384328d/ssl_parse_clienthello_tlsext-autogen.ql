/**
 * @name openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_parse_clienthello_tlsext
 * @id cpp/openssl/2b0532f3984324ebe1236a63d15893792384328d/ssl-parse-clienthello-tlsext
 * @description openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_parse_clienthello_tlsext CVE-2014-3513
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter val_976, Variable vsize_979, Variable vdata_981, Parameter vs_976) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_976
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="65279"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("SSL_get_srtp_profiles")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_976
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ssl_parse_clienthello_use_srtp_ext")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_976
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_981
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_979
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=val_976
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter val_976, Variable vtype_978, Variable vsize_979, Variable vdata_981, Parameter vs_976) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vtype_978
		and target_1.getAnOperand().(Literal).getValue()="14"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ssl_parse_clienthello_use_srtp_ext")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_976
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_981
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_979
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=val_976
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Parameter vs_976) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="next_proto_neg_seen"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_976
		and target_2.getRValue().(Literal).getValue()="1")
}

from Function func, Parameter val_976, Variable vtype_978, Variable vsize_979, Variable vdata_981, Parameter vs_976
where
not func_0(val_976, vsize_979, vdata_981, vs_976)
and func_1(val_976, vtype_978, vsize_979, vdata_981, vs_976)
and val_976.getType().hasName("int *")
and vtype_978.getType().hasName("unsigned short")
and vsize_979.getType().hasName("unsigned short")
and vdata_981.getType().hasName("unsigned char *")
and vs_976.getType().hasName("SSL *")
and func_2(vs_976)
and val_976.getParentScope+() = func
and vtype_978.getParentScope+() = func
and vsize_979.getParentScope+() = func
and vdata_981.getParentScope+() = func
and vs_976.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
