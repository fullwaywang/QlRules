/**
 * @name openssl-1250f12613b61758675848f6600ebd914ccd7636-dtls1_process_out_of_seq_message
 * @id cpp/openssl/1250f12613b61758675848f6600ebd914ccd7636/dtls1-process-out-of-seq-message
 * @description openssl-1250f12613b61758675848f6600ebd914ccd7636-dtls1_process_out_of_seq_message CVE-2014-3506
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfrag_len_715, Variable vitem_713, Parameter vs_709) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfrag_len_715
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dtls1_max_handshake_message_len")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_709
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_713
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="handshake_read_seq"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="20")
}

predicate func_1(Variable vfrag_len_715, Parameter vmsg_hdr_709, Parameter vok_709, Parameter vs_709) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vfrag_len_715
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vfrag_len_715
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="msg_len"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_hdr_709
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_reassemble_fragment")
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_709
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmsg_hdr_709
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vok_709)
}

predicate func_2(Parameter vmsg_hdr_709, Parameter vok_709, Parameter vs_709) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("dtls1_reassemble_fragment")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_709
		and target_2.getArgument(1).(VariableAccess).getTarget()=vmsg_hdr_709
		and target_2.getArgument(2).(VariableAccess).getTarget()=vok_709)
}

from Function func, Variable vfrag_len_715, Parameter vmsg_hdr_709, Parameter vok_709, Variable vitem_713, Parameter vs_709
where
not func_0(vfrag_len_715, vitem_713, vs_709)
and vfrag_len_715.getType().hasName("unsigned long")
and func_1(vfrag_len_715, vmsg_hdr_709, vok_709, vs_709)
and vmsg_hdr_709.getType().hasName("hm_header_st *")
and vok_709.getType().hasName("int *")
and vitem_713.getType().hasName("pitem *")
and vs_709.getType().hasName("SSL *")
and func_2(vmsg_hdr_709, vok_709, vs_709)
and vfrag_len_715.getParentScope+() = func
and vmsg_hdr_709.getParentScope+() = func
and vok_709.getParentScope+() = func
and vitem_713.getParentScope+() = func
and vs_709.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
