/**
 * @name openssl-fb0bc2b273bcc2d5401dd883fe869af4fc74bb21-ssl_scan_serverhello_tlsext
 * @id cpp/openssl/fb0bc2b273bcc2d5401dd883fe869af4fc74bb21/ssl-scan-serverhello-tlsext
 * @description openssl-fb0bc2b273bcc2d5401dd883fe869af4fc74bb21-ssl_scan_serverhello_tlsext CVE-2014-3509
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_2579, Variable vtype_2582, Variable vecpointformatlist_length_2643) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hit"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2579
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ecpointformatlist"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vecpointformatlist_length_2643
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_2582
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="11")
}

predicate func_1(Parameter vs_2579, Variable vtype_2582) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ecpointformatlist_length"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2579
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_2582
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="11")
}

predicate func_2(Parameter vs_2579, Variable vtype_2582) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tlsext_ecpointformatlist"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2579
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tlsext_ecpointformatlist"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2579
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_2582
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="11")
}

predicate func_3(Parameter vs_2579, Variable vtype_2582, Variable vecpointformatlist_length_2643) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ecpointformatlist_length"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2579
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vecpointformatlist_length_2643
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_2582
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="11")
}

predicate func_4(Parameter vs_2579, Variable vtype_2582, Variable vsdata_2642, Variable vecpointformatlist_length_2643) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tlsext_ecpointformatlist"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2579
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsdata_2642
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vecpointformatlist_length_2643
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_2582
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="11")
}

predicate func_5(Parameter vs_2579, Parameter val_2579, Variable vsize_2583) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tlsext_hostname"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2579
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_2583
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val_2579
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="112"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vs_2579, Parameter val_2579, Variable vtype_2582, Variable vsize_2583, Variable vsdata_2642, Variable vecpointformatlist_length_2643
where
not func_0(vs_2579, vtype_2582, vecpointformatlist_length_2643)
and func_1(vs_2579, vtype_2582)
and func_2(vs_2579, vtype_2582)
and func_3(vs_2579, vtype_2582, vecpointformatlist_length_2643)
and func_4(vs_2579, vtype_2582, vsdata_2642, vecpointformatlist_length_2643)
and vs_2579.getType().hasName("SSL *")
and func_5(vs_2579, val_2579, vsize_2583)
and val_2579.getType().hasName("int *")
and vtype_2582.getType().hasName("unsigned short")
and vsize_2583.getType().hasName("unsigned short")
and vsdata_2642.getType().hasName("unsigned char *")
and vecpointformatlist_length_2643.getType().hasName("int")
and vs_2579.getParentScope+() = func
and val_2579.getParentScope+() = func
and vtype_2582.getParentScope+() = func
and vsize_2583.getParentScope+() = func
and vsdata_2642.getParentScope+() = func
and vecpointformatlist_length_2643.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
