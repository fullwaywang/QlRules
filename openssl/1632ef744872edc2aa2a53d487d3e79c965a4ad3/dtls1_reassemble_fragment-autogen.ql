/**
 * @name openssl-1632ef744872edc2aa2a53d487d3e79c965a4ad3-dtls1_reassemble_fragment
 * @id cpp/openssl/1632ef744872edc2aa2a53d487d3e79c965a4ad3/dtls1-reassemble-fragment
 * @description openssl-1632ef744872edc2aa2a53d487d3e79c965a4ad3-dtls1_reassemble_fragment CVE-2014-0195
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmsg_hdr_592, Variable vfrag_594, Variable vitem_595) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="msg_len"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg_header"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfrag_594
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="msg_len"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_hdr_592
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem_595
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_594
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_595
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_4(Variable vfrag_594, Variable vitem_595) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_594
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem_595
		and target_4.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_595
		and target_4.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_5(Parameter vmsg_hdr_592) {
	exists(PointerDereferenceExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vmsg_hdr_592)
}

predicate func_6(Variable vfrag_594) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(ValueFieldAccess).getTarget().getName()="frag_off"
		and target_6.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg_header"
		and target_6.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfrag_594
		and target_6.getRValue().(Literal).getValue()="0")
}

predicate func_7(Variable vfrag_594, Variable vitem_595) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vfrag_594
		and target_7.getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem_595)
}

from Function func, Parameter vmsg_hdr_592, Variable vfrag_594, Variable vitem_595
where
not func_0(vmsg_hdr_592, vfrag_594, vitem_595)
and func_4(vfrag_594, vitem_595)
and vmsg_hdr_592.getType().hasName("hm_header_st *")
and func_5(vmsg_hdr_592)
and vfrag_594.getType().hasName("hm_fragment *")
and func_6(vfrag_594)
and vitem_595.getType().hasName("pitem *")
and func_7(vfrag_594, vitem_595)
and vmsg_hdr_592.getParentScope+() = func
and vfrag_594.getParentScope+() = func
and vitem_595.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
