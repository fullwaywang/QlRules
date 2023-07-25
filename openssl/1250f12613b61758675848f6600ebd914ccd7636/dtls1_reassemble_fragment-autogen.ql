/**
 * @name openssl-1250f12613b61758675848f6600ebd914ccd7636-dtls1_reassemble_fragment
 * @id cpp/openssl/1250f12613b61758675848f6600ebd914ccd7636/dtls1-reassemble-fragment
 * @description openssl-1250f12613b61758675848f6600ebd914ccd7636-dtls1_reassemble_fragment CVE-2014-3506
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmsg_hdr_597, Parameter vs_597) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="msg_len"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_hdr_597
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("dtls1_max_handshake_message_len")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_597
		and target_0.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_3(Parameter vmsg_hdr_597, Variable vfrag_len_603) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frag_off"
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_hdr_597
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vfrag_len_603
		and target_3.getLesserOperand().(PointerFieldAccess).getTarget().getName()="msg_len"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_hdr_597
		and target_3.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_4(Parameter vmsg_hdr_597, Variable vfrag_len_603, Variable vmax_len_603) {
	exists(AddExpr target_4 |
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="frag_off"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_hdr_597
		and target_4.getAnOperand().(VariableAccess).getTarget()=vfrag_len_603
		and target_4.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vmax_len_603
		and target_4.getParent().(GTExpr).getParent().(IfStmt).getThen() instanceof GotoStmt)
}

predicate func_6(Function func) {
	exists(VariableDeclarationEntry target_6 |
		target_6.getType() instanceof LongType
		and target_6.getDeclaration().getParentScope+() = func)
}

predicate func_7(Variable vmax_len_603, Parameter vs_597, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="17740"
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="max_cert_list"
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_597
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_len_603
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="max_cert_list"
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_597
		and target_7.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_len_603
		and target_7.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getValue()="17740"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Variable vmax_len_603, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmax_len_603
		and target_8.getThen().(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

from Function func, Parameter vmsg_hdr_597, Variable vfrag_len_603, Variable vmax_len_603, Parameter vs_597
where
not func_0(vmsg_hdr_597, vs_597)
and func_3(vmsg_hdr_597, vfrag_len_603)
and func_4(vmsg_hdr_597, vfrag_len_603, vmax_len_603)
and func_6(func)
and func_7(vmax_len_603, vs_597, func)
and func_8(vmax_len_603, func)
and vmsg_hdr_597.getType().hasName("hm_header_st *")
and vfrag_len_603.getType().hasName("unsigned long")
and vs_597.getType().hasName("SSL *")
and vmsg_hdr_597.getParentScope+() = func
and vfrag_len_603.getParentScope+() = func
and vmax_len_603.getParentScope+() = func
and vs_597.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
