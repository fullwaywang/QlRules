/**
 * @name openssl-bff1ce4e6a1c57c3d0a5f9e4f85ba6385fccfe8b-dtls1_process_out_of_seq_message
 * @id cpp/openssl/bff1ce4e6a1c57c3d0a5f9e4f85ba6385fccfe8b/dtls1-process-out-of-seq-message
 * @description openssl-bff1ce4e6a1c57c3d0a5f9e4f85ba6385fccfe8b-dtls1_process_out_of_seq_message CVE-2014-3505
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfrag_712, Variable vitem_713) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_713
		and target_0.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag_712)
}

predicate func_1(Variable vfrag_712) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vfrag_712
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag_712)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vitem_713, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_713
		and target_4.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vitem_713
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Variable vfrag_712, Variable vitem_713
where
not func_0(vfrag_712, vitem_713)
and func_1(vfrag_712)
and func_3(func)
and func_4(vitem_713, func)
and vfrag_712.getType().hasName("hm_fragment *")
and vitem_713.getType().hasName("pitem *")
and vfrag_712.getParentScope+() = func
and vitem_713.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
