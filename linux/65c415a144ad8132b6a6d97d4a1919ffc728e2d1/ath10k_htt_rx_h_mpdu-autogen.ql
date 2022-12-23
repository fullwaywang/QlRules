/**
 * @name linux-65c415a144ad8132b6a6d97d4a1919ffc728e2d1-ath10k_htt_rx_h_mpdu
 * @id cpp/linux/65c415a144ad8132b6a6d97d4a1919ffc728e2d1/ath10k_htt_rx_h_mpdu
 * @description linux-65c415a144ad8132b6a6d97d4a1919ffc728e2d1-ath10k_htt_rx_h_mpdu CVE-2020-26145
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Parameter var_1818, Parameter vfrag_1825, Variable vmsdu_1829) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ath10k_htt_rx_h_frag_multicast_check")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=var_1818
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmsdu_1829
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vfrag_1825)
}

predicate func_3(Parameter vamsdu_1819, Variable vmsdu_1829, Variable vtemp_1829, Variable vfrag_pn_check_1842) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtemp_1829
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="prev"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsdu_1829
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__skb_unlink")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmsdu_1829
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vamsdu_1819
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_kfree_skb_any")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmsdu_1829
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmsdu_1829
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtemp_1829
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_pn_check_1842
		and target_3.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_3.getThen().(BlockStmt).getStmt(6).(ContinueStmt).toString() = "continue;")
}

predicate func_5(Parameter vamsdu_1819, Variable vmsdu_1829, Variable vtemp_1829, Variable vfrag_pn_check_1842) {
	exists(NotExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vfrag_pn_check_1842
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtemp_1829
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="prev"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsdu_1829
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__skb_unlink")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmsdu_1829
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vamsdu_1819
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_kfree_skb_any")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmsdu_1829)
}

predicate func_6(Parameter var_1818, Parameter vpeer_id_1824, Variable vmsdu_1829, Variable venctype_1832) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("ath10k_htt_rx_h_frag_pn_check")
		and target_6.getArgument(0).(VariableAccess).getTarget()=var_1818
		and target_6.getArgument(1).(VariableAccess).getTarget()=vmsdu_1829
		and target_6.getArgument(2).(VariableAccess).getTarget()=vpeer_id_1824
		and target_6.getArgument(3).(Literal).getValue()="0"
		and target_6.getArgument(4).(VariableAccess).getTarget()=venctype_1832)
}

predicate func_7(Parameter vfill_crypt_header_1821, Parameter vfrag_1825) {
	exists(LogicalAndExpr target_7 |
		target_7.getAnOperand().(VariableAccess).getTarget()=vfrag_1825
		and target_7.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vfill_crypt_header_1821)
}

from Function func, Parameter vamsdu_1819, Parameter var_1818, Parameter vfill_crypt_header_1821, Parameter vpeer_id_1824, Parameter vfrag_1825, Variable vmsdu_1829, Variable vtemp_1829, Variable venctype_1832, Variable vfrag_pn_check_1842
where
not func_2(var_1818, vfrag_1825, vmsdu_1829)
and not func_3(vamsdu_1819, vmsdu_1829, vtemp_1829, vfrag_pn_check_1842)
and func_5(vamsdu_1819, vmsdu_1829, vtemp_1829, vfrag_pn_check_1842)
and vamsdu_1819.getType().hasName("sk_buff_head *")
and var_1818.getType().hasName("ath10k *")
and func_6(var_1818, vpeer_id_1824, vmsdu_1829, venctype_1832)
and vpeer_id_1824.getType().hasName("u16")
and vfrag_1825.getType().hasName("bool")
and func_7(vfill_crypt_header_1821, vfrag_1825)
and vmsdu_1829.getType().hasName("sk_buff *")
and vtemp_1829.getType().hasName("sk_buff *")
and venctype_1832.getType().hasName("htt_rx_mpdu_encrypt_type")
and vfrag_pn_check_1842.getType().hasName("bool")
and vamsdu_1819.getParentScope+() = func
and var_1818.getParentScope+() = func
and vfill_crypt_header_1821.getParentScope+() = func
and vpeer_id_1824.getParentScope+() = func
and vfrag_1825.getParentScope+() = func
and vmsdu_1829.getParentScope+() = func
and vtemp_1829.getParentScope+() = func
and venctype_1832.getParentScope+() = func
and vfrag_pn_check_1842.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
