/**
 * @name haproxy-2e6bf0a2722866ae0128a4392fa2375bd1f03ff8-fcgi_encode_record_hdr
 * @id cpp/haproxy/2e6bf0a2722866ae0128a4392fa2375bd1f03ff8/fcgi-encode-record-hdr
 * @description haproxy-2e6bf0a2722866ae0128a4392fa2375bd1f03ff8-src/fcgi.c-fcgi_encode_record_hdr CVE-2023-0836
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vout_36, ExprStmt target_2, ExprStmt target_3) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_0.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_36
		and target_0.getLValue().(ArrayExpr).getArrayOffset() instanceof PostfixIncrExpr
		and target_0.getRValue().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlen_38, PostfixIncrExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vlen_38
}

predicate func_2(Parameter vout_36, Variable vlen_38, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="area"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_36
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlen_38
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="padding"
}

predicate func_3(Parameter vout_36, Variable vlen_38, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_36
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_38
}

from Function func, Parameter vout_36, Variable vlen_38, PostfixIncrExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vout_36, target_2, target_3)
and func_1(vlen_38, target_1)
and func_2(vout_36, vlen_38, target_2)
and func_3(vout_36, vlen_38, target_3)
and vout_36.getType().hasName("buffer *")
and vlen_38.getType().hasName("size_t")
and vout_36.getParentScope+() = func
and vlen_38.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
