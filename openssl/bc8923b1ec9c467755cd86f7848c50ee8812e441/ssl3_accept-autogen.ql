/**
 * @name openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_accept
 * @id cpp/openssl/bc8923b1ec9c467755cd86f7848c50ee8812e441/ssl3-accept
 * @description openssl-bc8923b1ec9c467755cd86f7848c50ee8812e441-ssl3_accept CVE-2014-0224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_213) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_213
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="128"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_213)
}

predicate func_3(Parameter vs_213) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="next_state"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_213
		and target_3.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="8720"
		and target_3.getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="next_proto_neg_seen"
		and target_3.getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_3.getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_213)
}

predicate func_4(Variable vdgst_num_643, Parameter vs_213) {
	exists(ArrayExpr target_4 |
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="handshake_dgst"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_213
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vdgst_num_643
		and target_4.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("EVP_MD_CTX_md"))
}

predicate func_5(Parameter vs_213) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_213
		and target_5.getRValue().(BitwiseOrExpr).getValue()="8640")
}

predicate func_6(Parameter vs_213) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="next_proto_neg_seen"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_213)
}

from Function func, Variable vdgst_num_643, Parameter vs_213
where
not func_0(vs_213)
and func_3(vs_213)
and vs_213.getType().hasName("SSL *")
and func_4(vdgst_num_643, vs_213)
and func_5(vs_213)
and func_6(vs_213)
and vdgst_num_643.getParentScope+() = func
and vs_213.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
