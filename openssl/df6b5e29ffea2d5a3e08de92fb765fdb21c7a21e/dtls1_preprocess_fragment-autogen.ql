/**
 * @name openssl-df6b5e29ffea2d5a3e08de92fb765fdb21c7a21e-dtls1_preprocess_fragment
 * @id cpp/openssl/df6b5e29ffea2d5a3e08de92fb765fdb21c7a21e/dtls1-preprocess-fragment
 * @description openssl-df6b5e29ffea2d5a3e08de92fb765fdb21c7a21e-dtls1_preprocess_fragment CVE-2016-6307
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_391, Variable vmsg_len_393) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmsg_len_393
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dtls1_max_handshake_message_len")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_391
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="288"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="152"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_1(Variable vfrag_off_393, Variable vfrag_len_393, Variable vmsg_len_393) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vfrag_off_393
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vfrag_len_393
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vmsg_len_393
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="288"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="152"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_2(Parameter vmsg_hdr_391, Variable vmsg_len_393) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vmsg_len_393
		and target_2.getRValue().(PointerFieldAccess).getTarget().getName()="msg_len"
		and target_2.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_hdr_391)
}

from Function func, Parameter vs_391, Parameter vmsg_hdr_391, Variable vfrag_off_393, Variable vfrag_len_393, Variable vmsg_len_393
where
not func_0(vs_391, vmsg_len_393)
and func_1(vfrag_off_393, vfrag_len_393, vmsg_len_393)
and vs_391.getType().hasName("SSL *")
and vfrag_off_393.getType().hasName("size_t")
and vfrag_len_393.getType().hasName("size_t")
and vmsg_len_393.getType().hasName("size_t")
and func_2(vmsg_hdr_391, vmsg_len_393)
and vs_391.getParentScope+() = func
and vmsg_hdr_391.getParentScope+() = func
and vfrag_off_393.getParentScope+() = func
and vfrag_len_393.getParentScope+() = func
and vmsg_len_393.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
