/**
 * @name ndpi-23594f036536468072198a57c59b6e9d63caf6ce-extractRDNSequence
 * @id cpp/ndpi/23594f036536468072198a57c59b6e9d63caf6ce/extractRDNSequence
 * @description ndpi-23594f036536468072198a57c59b6e9d63caf6ce-src/lib/protocols/tls.c-extractRDNSequence CVE-2020-15474
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrdnSeqBuf_offset_192, Parameter vrdnSeqBuf_len_193, AddressOfExpr target_1, SubExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vrdnSeqBuf_offset_192
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrdnSeqBuf_len_193
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vrdnSeqBuf_offset_192, AddressOfExpr target_1) {
		target_1.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vrdnSeqBuf_offset_192
}

predicate func_2(Parameter vrdnSeqBuf_offset_192, Parameter vrdnSeqBuf_len_193, SubExpr target_2) {
		target_2.getLeftOperand().(VariableAccess).getTarget()=vrdnSeqBuf_len_193
		and target_2.getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vrdnSeqBuf_offset_192
}

from Function func, Parameter vrdnSeqBuf_offset_192, Parameter vrdnSeqBuf_len_193, AddressOfExpr target_1, SubExpr target_2
where
not func_0(vrdnSeqBuf_offset_192, vrdnSeqBuf_len_193, target_1, target_2, func)
and func_1(vrdnSeqBuf_offset_192, target_1)
and func_2(vrdnSeqBuf_offset_192, vrdnSeqBuf_len_193, target_2)
and vrdnSeqBuf_offset_192.getType().hasName("u_int *")
and vrdnSeqBuf_len_193.getType().hasName("u_int")
and vrdnSeqBuf_offset_192.getParentScope+() = func
and vrdnSeqBuf_len_193.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
